import type { ArenaEvent } from "../../../packages/contracts/src/index.ts";
import { isSafePublicText, safeFallback, sanitizePublicEvent } from
  "../../../packages/contracts/src/public-safety.ts";
import { presentationEventSummary } from "./presentation-mode.ts";

export interface PublicDetail { label: string; value: string; }

const money = (cents: number) => (cents / 100).toLocaleString("pt-BR", {
  style: "currency", currency: "BRL", maximumFractionDigits: 0 });
const number = (value: unknown) => Number(value).toLocaleString("pt-BR");

export function publicEventDetails(raw: ArenaEvent, presentation = false): PublicDetail[] {
  const event = sanitizePublicEvent(raw);
  const data = event.public;
  if (presentation) return [{ label: "Evento", value: presentationEventSummary(event) }];
  const text = (value: unknown) => typeof value === "string" && isSafePublicText(value) ?
    value : safeFallback(event.area);
  switch (event.type) {
    case "attack.attempted":
      return [{ label: "Padrão observado", value: text(data.technique_label) }];
    case "attack.succeeded":
      return [{ label: "Classe da falha", value: text(data.weakness_class_label) }];
    case "impact.caused":
      return [{ label: "Impacto financeiro simulado", value: money(Number(data.loss_cents)) },
        { label: "Clientes afetados", value: number(data.customers_affected) },
        { label: "Registros expostos", value: number(data.records_exposed) }];
    case "sentinel.alert":
      return [{ label: "Severidade", value: ({ low: "Baixa", medium: "Média", high: "Alta",
        critical: "Crítica" } as Record<string, string>)[String(data.severity)] ?? "Em análise" }];
    case "context.handoff": {
      const names: Record<string, string> = { incident_dossier: "Dossiê do incidente",
        review_feedback: "Revisão anterior", candidate: "Patch candidato",
        ci_result: "Resultado de CI", acceptance_invariants: "Invariantes de aceite" };
      const inherited = Array.isArray(data.inherited) ? data.inherited.map((item) =>
        names[String(item)] ?? "Contexto verificado") : [];
      return [{ label: "Nasceu sabendo", value: inherited.join(" · ") || "Contexto inicial" },
        ...(typeof data.context_sha256 === "string" ?
          [{ label: "Hash do contexto", value: data.context_sha256 }] : [])];
    }
    case "review.rejected":
      return [{ label: "Motivo público", value: text(data.reason_pt) }];
    case "regression.result":
      return [{ label: "Testes aprovados", value: `${number(data.pass)} de ${number(data.total)}` },
        { label: "Falhas", value: number(data.fail) }];
    case "damage.assessed":
      return [{ label: "Valor pendente", value: money(Number(data.loss_cents)) },
        { label: "Clientes afetados", value: number(data.customers_affected) },
        ...(typeof data.blocked_cents === "number" ?
          [{ label: "Bloqueado no MED", value: money(data.blocked_cents) }] : []),
        ...(typeof data.escaped_cents === "number" ?
          [{ label: "Fora do bloqueio", value: money(data.escaped_cents) }] : [])];
    case "damage.restored":
      return [{ label: "Valor restaurado", value: money(Number(data.restored_cents)) },
        { label: "Clientes reparados", value: number(data.customers_made_whole) },
        ...(typeof data.recovered_cents === "number" ?
          [{ label: "Recuperado", value: money(data.recovered_cents) }] : []),
        ...(typeof data.absorbed_cents === "number" ?
          [{ label: "Absorvido pelo banco", value: money(data.absorbed_cents) }] : [])];
    case "feature.launched":
      return [{ label: "Recurso", value: text(data.name_pt) },
        { label: "Resumo", value: text(data.summary_pt) }];
    case "round.ended": {
      const score = data.score as { red_points: number; blue_points: number };
      return [{ label: "Equipe vermelha", value: score.red_points.toFixed(1) },
        { label: "Equipe azul", value: score.blue_points.toFixed(1) }];
    }
    default: return [];
  }
}
