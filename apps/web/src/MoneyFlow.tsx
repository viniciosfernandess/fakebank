import { useEffect, useState } from "react";
import { presentationInstitution } from "../../../packages/contracts/src/money-flow-presentation.ts";

export interface MoneyFlowSnapshot {
  incidentId?: string | null;
  edges: { from: string; to: string; kind: "payment" | "transfer" | "cashout" }[];
  med: { status?: "open" | "refunded" | "resolved" | "rejected";
    recovery: "pending" | "none" | "partial" | "full";
    institutions?: { name: string; state: "held" | "recovered" | "mixed" | "released" }[];
    accounts?: { name: string; slot: number;
      state: "held" | "recovered" | "mixed" | "released" }[] } | null;
}

const recoveryLabel: Record<NonNullable<MoneyFlowSnapshot["med"]>["recovery"], string> = {
  pending: "MED em análise", none: "Sem recuperação",
  partial: "Recuperação parcial", full: "Recuperação integral",
};
const institutionLabel: Record<NonNullable<NonNullable<MoneyFlowSnapshot["med"]>["institutions"]>[number]["state"], string> = {
  held: "saldo sob MED", recovered: "saldo recuperado", mixed: "saldo retido e recuperado",
  released: "bloqueio encerrado sem devolução",
};

export function MoneyFlow({ incidentId, presentation, replaySnapshot }: {
  incidentId: string | null | undefined; presentation: boolean;
  replaySnapshot?: MoneyFlowSnapshot | null;
}) {
  const replay = replaySnapshot !== undefined;
  const [loaded, setLoaded] = useState<{
    selectionId: string | null; presentation: boolean;
    snapshot: MoneyFlowSnapshot | null; locked: boolean;
  } | null>(null);
  const current = loaded?.selectionId === incidentId && loaded?.presentation === presentation ? loaded : null;
  const snapshot = replay ? replaySnapshot : current?.snapshot;
  const locked = !replay && (current?.locked ?? false);
  const medByInstitution = new Map(snapshot?.med?.institutions?.map((institution) =>
    [institution.name, institution.state] as const) ?? []);
  const medSummary = snapshot?.med?.status === "rejected" ?
    "Contestação não aprovada" : snapshot?.med ? recoveryLabel[snapshot.med.recovery] : null;
  useEffect(() => {
    setLoaded(null);
    if (incidentId === undefined || replay) return;
    let disposed = false;
    let controller: AbortController | undefined;
    const refresh = () => {
      controller?.abort();
      controller = new AbortController();
      const signal = controller.signal;
      const suffix = incidentId ? `/${encodeURIComponent(incidentId)}` : "";
      const operatorPath = `/api/operator/bank/money-flow${suffix}`;
      const presentationPath = `/api/presentation/bank/money-flow${suffix}`;
      void fetch(presentation ? presentationPath : operatorPath, { cache: "no-store", signal })
        .then((response) => {
          const denied = !presentation && (response.status === 401 || response.status === 403);
          return (response.ok ? response.json() as Promise<MoneyFlowSnapshot> :
            Promise.resolve(null)).then((value) => ({ value, denied }));
        })
        .then(({ value, denied }) => { if (!disposed && !signal.aborted)
          setLoaded({ selectionId: incidentId, presentation, snapshot: value, locked: denied }); })
        .catch(() => { if (!disposed && !signal.aborted)
          setLoaded({ selectionId: incidentId, presentation, snapshot: null, locked: false }); });
    };
    refresh();
    const interval = window.setInterval(refresh, 5000);
    return () => { disposed = true; window.clearInterval(interval); controller?.abort(); };
  }, [incidentId, presentation, replay]);
  return <section className="money-flow" aria-label="Fluxo do Pix entre instituições">
    <div className="money-flow-heading"><small>INCIDENTE PIX</small>
      <strong>Fluxo entre instituições</strong>
      {replay && <small>REPRODUÇÃO</small>}
      {medSummary && <span>{medSummary.toUpperCase()}</span>}</div>
    {incidentId === undefined ? <p>Não há fluxo Pix para a seleção atual.</p> :
      locked ? <p>Entre como operador local para consultar esta cadeia.</p> :
      !snapshot?.edges.length ? <p>{incidentId ?
        "Nenhum Pix interbancário vinculado a este incidente." :
        "Aguardando um incidente Pix com transferência vinculada."}</p> :
      <><small>{incidentId ? "INCIDENTE SELECIONADO" : "ÚLTIMA CADEIA VINCULADA"}</small>
      <ol>{snapshot.edges.map((edge, index) => {
        const medState = medByInstitution.get(edge.to);
        return <li key={`${index}-${edge.kind}`}>
        <span className="money-flow-node">{presentation ? presentationInstitution(edge.from) : edge.from}</span>
        <span className={`money-flow-link ${edge.kind}${medState ? ` med-${medState}` : ""}`}>
          <b aria-hidden="true">{medState === "held" || medState === "mixed" ? "🔒" :
            medState === "recovered" ? "↶" : "→"}</b>
          <small>{medState === "held" || medState === "mixed" ? "sob MED" :
            medState === "recovered" ? "recuperado" :
              medState === "released" ? "bloqueio encerrado" :
              edge.kind === "cashout" ? "saída confirmada" : "liquidado"}</small>
        </span>
        <span className="money-flow-node">{presentation ? presentationInstitution(edge.to) : edge.to}</span>
      </li>; })}</ol></>}
    {snapshot?.med?.institutions && (!presentation || snapshot.med.accounts) &&
      <div className="money-flow-med" aria-label="Situação do MED">
      <strong>{medSummary}</strong>
      {!presentation && snapshot.med.institutions.map((institution) => <span
        key={institution.name}>{institution.name}: {institutionLabel[institution.state]}</span>)}
      {snapshot.med.accounts?.map((account) => <span
        key={`${account.name}:${account.slot}`}>{account.name} · saldo {account.slot}: {
          institutionLabel[account.state]}</span>)}
    </div>}
  </section>;
}
