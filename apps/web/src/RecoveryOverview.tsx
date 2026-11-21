import type { ArenaEvent } from "../../../packages/contracts/src/index.ts";
import { recoveryOverview } from "./recovery-overview.ts";

const money = (cents: number) => (cents / 100).toLocaleString("pt-BR", {
  style: "currency", currency: "BRL", maximumFractionDigits: 0,
});

export function RecoveryOverview({ events, presentation }: {
  events: readonly ArenaEvent[];
  presentation: boolean;
}) {
  const summary = recoveryOverview(events);
  if (summary.impactCents === null && summary.restoredCents === null) return null;
  const amount = (cents: number | null) => cents === null ? "Sem registro" :
    presentation ? "Valor reservado" : money(cents);
  const hasBreakdown = summary.recoveredCents !== null || summary.absorbedCents !== null;
  return <section className="recovery-overview" aria-label="Dano e recuperação da rodada">
    <div><small>IMPACTO CONFIRMADO</small><strong>{amount(summary.impactCents)}</strong></div>
    <div><small>DEVOLVIDO A CLIENTES</small><strong>{amount(summary.restoredCents)}</strong></div>
    <div><small>RECUPERADO NA CADEIA</small><strong>{hasBreakdown ?
      amount(summary.recoveredCents) : "Origem ainda não detalhada"}</strong></div>
  </section>;
}
