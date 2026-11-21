import type { ArenaEvent } from "../../../packages/contracts/src/index.ts";

export function initialPresentationMode(search: string, viewportWidth: number): boolean {
  const mode = new URLSearchParams(search).get("mode");
  if (mode === "presenter") return true;
  if (mode === "operator") return false;
  return viewportWidth >= 1600;
}

const eventLabels: Record<string, string> = {
  "attack.attempted": "Tentativa de ataque observada",
  "attack.succeeded": "Falha confirmada",
  "impact.caused": "Impacto financeiro observado",
  "sentinel.alert": "Alerta da defesa emitido",
  "incident.opened": "Incidente aberto para investigação",
  "containment.applied": "Contenção aplicada",
  "review.rejected": "Correção devolvida para revisão",
  "review.approved": "Correção aprovada",
  "patch.merged": "Correção integrada",
  "deploy.succeeded": "Correção implantada",
  "deploy.rolled_back": "Implantação revertida",
  "regression.result": "Regressão verificada",
  "damage.assessed": "Dano avaliado",
  "damage.restored": "Recuperação registrada",
  "feature.launched": "Nova proteção ativada",
  "round.ended": "Rodada encerrada",
};

export function presentationEventSummary(event: Pick<ArenaEvent, "type">): string {
  return eventLabels[event.type] ?? "Atividade do banco registrada";
}

export function presentationShareUrl(path: string, origin: string): string {
  const url = new URL(path, origin);
  url.searchParams.set("mode", "presenter");
  return url.href;
}

export function pathWithPresentationMode(path: string, currentSearch: string): string {
  const mode = new URLSearchParams(currentSearch).get("mode");
  if (mode !== "presenter" && mode !== "operator") return path;
  const [pathname, hash = ""] = path.split("#", 2);
  const [base, query = ""] = pathname!.split("?", 2);
  const params = new URLSearchParams(query);
  if (!params.has("mode")) params.set("mode", mode);
  return `${base}?${params}${hash ? `#${hash}` : ""}`;
}
