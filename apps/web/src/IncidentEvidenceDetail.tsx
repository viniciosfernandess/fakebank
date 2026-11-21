export interface IncidentEvidenceDetailData {
  key: string;
  kind: "patch.diff" | "ci.result" | "ci.failure" | "dossier.review" |
    "dossier.incident_map" | "dossier.root_cause" | "dossier.fix_design";
  attempt: number | null;
  detail: Record<string, unknown>;
}

function text(value: unknown): string { return typeof value === "string" ? value : ""; }
function step(value: unknown): { ok: boolean; output: string; duration_ms: number | null } | null {
  if (!value || typeof value !== "object") return null;
  const item = value as Record<string, unknown>;
  return { ok: item.ok === true, output: text(item.output),
    duration_ms: typeof item.duration_ms === "number" ? item.duration_ms : null };
}
function strings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}
function records(value: unknown): Record<string, unknown>[] {
  return Array.isArray(value) ? value.filter((item): item is Record<string, unknown> =>
    item !== null && typeof item === "object" && !Array.isArray(item)) : [];
}
function DetailList({ title, values }: { title: string; values: string[] }) {
  return values.length > 0 && <section><strong>{title}</strong><ul>{values.map((value, index) =>
    <li key={index}>{value}</li>)}</ul></section>;
}
const scopeLabel: Record<string, string> = {
  single_account: "uma conta", multi_account: "múltiplas contas",
  cross_institution: "entre instituições", systemic: "sistêmico", unknown: "indefinido",
};
const stageLabel: Record<string, string> = {
  entry: "entrada", movement: "movimentação", persistence: "persistência", impact: "impacto",
};
const decisionLabel: Record<string, string> = {
  verified: "verificada", needs_human: "revisão humana necessária", build: "construir",
};
const rootClassLabel: Record<string, string> = {
  missing_check: "checagem ausente", wrong_order_of_checks: "ordem de checagens",
  race: "concorrência", rounding: "arredondamento", authz_gap: "autorização",
  rate_gap: "limite de frequência", rule_gap: "regra de risco",
  state_machine_gap: "transição de estado", data_exposure: "exposição de dados",
  unknown: "indefinida",
};

export function IncidentEvidenceDetail({ evidence, onClose }: {
  evidence: IncidentEvidenceDetailData; onClose: () => void;
}) {
  const detail = evidence.detail;
  const steps = evidence.kind === "ci.result" ? [
    ["Prova antes", "red_first_before"], ["Prova depois", "red_first_after"],
    ["Tipos", "typecheck"], ["Testes do banco", "world_tests"],
  ] as const : [];
  const flowPoint = records([detail.flow_point])[0];
  return <div className="soc-evidence-detail" role="region" aria-label="Detalhes do Case File">
    <div className="soc-evidence-detail-heading"><h4>{evidence.kind === "patch.diff" ? "Diff candidato" :
      evidence.kind === "ci.result" ? "Resultados da CI" :
        evidence.kind === "ci.failure" ? "Falha da CI" :
          evidence.kind === "dossier.review" ? "Veredito do revisor" :
            evidence.kind === "dossier.incident_map" ? "Mapa forense" :
              evidence.kind === "dossier.root_cause" ? "Causa raiz" : "Desenho da correção"}
      {evidence.attempt ? ` · tentativa ${evidence.attempt}` : ""}</h4>
      <button onClick={onClose} aria-label="Fechar detalhes da evidência">×</button></div>
    {evidence.kind === "patch.diff" && <>
      <small>SHA-256 {text(detail.sha256) || "indisponível"}{detail.truncated ?
        " · diff parcial" : ""}</small>
      <pre>{text(detail.diff) || "Diff indisponível."}</pre>
    </>}
    {evidence.kind === "ci.result" && <>
      <p>{detail.ready_for_review ? "Pronta para revisão" : "Com pendências"}
        {text(detail.red_first) ? ` · prova antes/depois: ${text(detail.red_first)}` : ""}</p>
      {steps.map(([label, key]) => {
        const result = step(detail[key]);
        const status = !result ? "não executado" : key === "red_first_before" ?
          result.ok ? "passou antes do patch; prova inválida" : "falhou antes do patch (esperado)" :
          result.ok ? "aprovado" : "falhou";
        return <section key={key}><strong>{label}: {status}</strong>{result?.duration_ms !== null && result?.duration_ms !== undefined &&
          <small> · {(result.duration_ms / 1000).toFixed(1)} s</small>}
          {result?.output && <pre>{result.output}</pre>}</section>;
      })}
    </>}
    {evidence.kind === "ci.failure" && <>
      <p>Tipos {detail.typecheck ? "aprovados" : "pendentes"} · testes {
        detail.world_tests ? "aprovados" : "pendentes"}</p>
      <pre>{text(detail.failure_output) || "Sem saída registrada."}</pre>
    </>}
    {evidence.kind === "dossier.review" && <>
      <p>Veredito: {text(detail.verdict) || "não informado"}</p>
      {Array.isArray(detail.findings) && detail.findings.length > 0 && <ul>{detail.findings
        .map((value, index) => {
          const finding = value && typeof value === "object" ?
            value as Record<string, unknown> : {};
          return <li key={index}><strong>{text(finding.severity) || "Achado"}</strong>: {
            text(finding.issue) || "Sem descrição"}</li>;
        })}</ul>}
      {strings(detail.reasons_for_rejection).length > 0 && <p>Motivos: {
        strings(detail.reasons_for_rejection).join(" · ")}</p>}
      {strings(detail.required_changes).length > 0 && <p>Mudanças pedidas: {
        strings(detail.required_changes).join(" · ")}</p>}
      {text(detail.diff_assessment) && <p>Avaliação do diff: {text(detail.diff_assessment)}</p>}
    </>}
    {evidence.kind === "dossier.incident_map" && <>
      <p>Alcance: <strong>{scopeLabel[text(detail.scope)] ?? "não informado"}</strong></p>
      <DetailList title="Linha do tempo forense" values={records(detail.timeline).map((item) =>
        `${text(item.ts)} · ${text(item.observation)} (${text(item.event_ref)})`)}/>
      <DetailList title="Etapas observadas" values={records(detail.observed_stages).map((item) =>
        `${stageLabel[text(item.stage)] ?? text(item.stage)} · ${text(item.observation)}`)}/>
      <DetailList title="Entidades" values={records(detail.entities).map((item) =>
        `${text(item.kind)} · ${text(item.id)}`)}/>
      <DetailList title="Indicadores" values={records(detail.indicators).map((item) =>
        `${text(item.kind)} · ${text(item.ref)} · provas: ${strings(item.evidence_refs).join(", ")}`)}/>
      <DetailList title="Referências de evidência" values={strings(detail.evidence_refs)}/>
      <DetailList title="Questões abertas" values={strings(detail.unresolved_questions)}/>
    </>}
    {evidence.kind === "dossier.root_cause" && <>
      <p>Decisão: <strong>{decisionLabel[text(detail.decision)] ?? "não informada"}</strong> · confiança {
        typeof detail.confidence === "number" ? `${Math.round(detail.confidence * 100)}%` : "indisponível"}</p>
      <p><strong>Classe:</strong> {rootClassLabel[text(detail.class)] ?? "não informada"}</p>
      <p>{text(detail.explanation)}</p>
      {flowPoint && <p><strong>Ponto do fluxo:</strong> {text(flowPoint.path)} · {
        text(flowPoint.symbol)} · {text(flowPoint.stage)}</p>}
      <DetailList title="Invariantes violadas" values={strings(detail.violated_invariants)}/>
      <DetailList title="Não pode quebrar" values={strings(detail.do_not_break)}/>
      <DetailList title="Provas de regressão" values={strings(detail.regression_ids)}/>
      <DetailList title="Referências de evidência" values={strings(detail.evidence_refs)}/>
      <DetailList title="Questões abertas" values={strings(detail.unresolved_questions)}/>
    </>}
    {evidence.kind === "dossier.fix_design" && <>
      <p>Decisão: <strong>{decisionLabel[text(detail.decision)] ?? "não informada"}</strong> · {text(detail.reason)}</p>
      <p><strong>Abordagem:</strong> {text(detail.approach)}</p>
      <DetailList title="Arquivos permitidos" values={strings(detail.allowed_paths)}/>
      <DetailList title="Invariantes de aceite" values={strings(detail.acceptance_invariants)}/>
      <DetailList title="Não pode quebrar" values={strings(detail.do_not_break)}/>
      <DetailList title="Plano de testes" values={strings(detail.test_plan)}/>
      <DetailList title="Alternativas" values={strings(detail.alternatives)}/>
      <DetailList title="Riscos" values={strings(detail.risks)}/>
      <DetailList title="Falhas anteriores abordadas" values={strings(detail.prior_failures_addressed)}/>
    </>}
  </div>;
}
