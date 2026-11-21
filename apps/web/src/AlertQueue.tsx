import type { ArenaEvent } from "../../../packages/contracts/src/index.ts";
import { alertAge, recentAlerts } from "./alert-queue.ts";

const areas: Record<string, string> = {
  auth: "Autenticação", accounts: "Contas", pix: "Pix", cards: "Cartões",
  loans: "Crédito", api_gateway: "Entrada digital", ledger: "Livro-razão",
};
const severities: Record<string, string> = {
  low: "BAIXA", medium: "MÉDIA", high: "ALTA", critical: "CRÍTICA",
};

export function AlertQueue({ events, nowMs, presentation, onSelect }: {
  events: ArenaEvent[];
  nowMs: number;
  presentation: boolean;
  onSelect: (event: ArenaEvent) => void;
}) {
  const alerts = recentAlerts(events, nowMs);
  return <section className="alert-queue" aria-label="Alertas recentes da rodada">
    <div className="subheading">FILA DE ALERTAS <span>{alerts.length} {alerts.length === 1 ? "RECENTE" : "RECENTES"}</span></div>
    {alerts.length ? <ol>{alerts.map((alert) => <li key={alert.event.seq}>
      <button onClick={() => onSelect(alert.event)}>
        <span className={`alert-severity ${alert.severity}`}>{severities[alert.severity]}</span>
        <span className="alert-copy"><strong>{areas[alert.area]}</strong>
          <small>{presentation ? "Regra oculta" : alert.ruleId} · Entidade protegida</small></span>
        <time>{alertAge(alert.ageSeconds)}</time>
      </button>
    </li>)}</ol> : <p>Nenhum alerta registrado.</p>}
  </section>;
}
