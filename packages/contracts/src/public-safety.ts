import type { ArenaEvent } from "./index.ts";

const unsafe = [
  /https?:\/\//i,
  /(?:GET|POST|PATCH|DELETE|PUT)\s+\//i,
  /\/(?:api|auth|pix|cards|loans|accounts|internal)\/[a-z0-9/_?=&.-]+/i,
  /\b(?:\d{1,3}\.){3}\d{1,3}\b/,
  /\b\d{11}\b/,
  /\b\d{3}\.\d{3}\.\d{3}-\d{2}\b/,
  /\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b/i,
  /\b(?:sk-ant-|sk-proj-|ghp_|github_pat_|xoxb-)[a-z0-9_-]+/i,
  /\b(?:bearer|api[_ -]?key|password|senha|refresh[_ -]?token|secret)\b/i,
  /\b[a-z][a-z0-9]*(?:_[a-z0-9]+)+\b/i,
  /\b(?:authorization|content-type|x-[a-z0-9-]{2,}|idempotency-key)\b/i,
  /\b[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/i,
  /\b[a-z][a-z0-9_]*_[0-9A-HJKMNP-TV-Z]{26}\b/,
  /\b[0-9A-HJKMNP-TV-Z]{26}\b/,
  /[<>]|\{[^{}]{0,200}\}|=>/,
  /\b(?:limite|threshold|janela|taxa)\s*(?:de|:|=)?\s*(?:R\$|US\$)?\s*\d/i,
  /```|`[^`]+`/,
  /\b(?:primeiro|depois|em seguida|passo a passo|execute|envie o corpo|altere o campo)\b/i,
  /[?&][a-z_]+=/i,
];
const narrativeKeys = new Set([
  "public_summary_pt", "text_pt", "summary_pt", "reason_pt", "goal_pt", "label_pt",
  "title_pt", "note_pt", "name_pt", "scope_label_pt", "pattern_label",
  "technique_label", "weakness_class_label", "invariant_label_pt", "defensive_diff_public",
  "headline_pt", "body_pt", "learning_pt", "takeaway_for_banks_pt", "reason",
]);
const narrativeListKeys = new Set(["failing_suites"]);
function mapChapters(value: unknown, transform: (text: string) => string): unknown {
  if (!Array.isArray(value)) return value;
  return value.map((chapter) => {
    if (!chapter || typeof chapter !== "object" || Array.isArray(chapter)) return chapter;
    const mapped = { ...chapter } as Record<string, unknown>;
    for (const key of ["title_pt", "body_pt"])
      if (typeof mapped[key] === "string") mapped[key] = transform(mapped[key]);
    return mapped;
  });
}

export function isSafePublicText(value: string): boolean {
  return value.length <= 280 && !unsafe.some((pattern) => pattern.test(value));
}

export function safeFallback(area?: string): string {
  const labels: Record<string, string> = { auth: "Autenticação", accounts: "Contas",
    pix: "Pix", cards: "Cartões", loans: "Crédito", api_gateway: "Entrada digital",
    ledger: "Livro razão" };
  const label = area && labels[area] || "Banco";
  return `${label}: impacto observado · causa em análise`;
}

export function sanitizePublicEvent<T extends ArenaEvent>(event: T): T {
  const fallback = safeFallback(event.area);
  const publicPayload: Record<string, unknown> = { ...event.public };
  for (const [key, value] of Object.entries(publicPayload)) {
    if (narrativeKeys.has(key) && typeof value === "string" && !isSafePublicText(value)) {
      publicPayload[key] = key === "defensive_diff_public" ? "Trecho reservado" : fallback;
    }
    if (narrativeListKeys.has(key) && Array.isArray(value))
      publicPayload[key] = value.map((item) => typeof item === "string" && isSafePublicText(item) ? item : fallback);
  }
  if (event.type === "narration.published") publicPayload.chapters =
    mapChapters(publicPayload.chapters, (value) => isSafePublicText(value) ? value : fallback);
  return { ...event, public_summary_pt: isSafePublicText(event.public_summary_pt) ? event.public_summary_pt : fallback,
    public: publicPayload };
}

export function maskPublicEventText<T extends ArenaEvent>(event: T): T {
  if (event.type === "money_flow.med_updated") return { ...event,
    public_summary_pt: "Conteúdo oculto temporariamente",
    public: { incident_id: event.public.incident_id,
      disclosure_seq: event.public.disclosure_seq, masked: true } };
  const publicPayload: Record<string, unknown> = { ...event.public };
  if (event.type === "money_flow.disclosed") publicPayload.edges = [];
  for (const [key, value] of Object.entries(publicPayload))
    if (narrativeKeys.has(key) && typeof value === "string") publicPayload[key] = "Conteúdo oculto temporariamente";
    else if (narrativeListKeys.has(key) && Array.isArray(value))
      publicPayload[key] = value.map(() => "Conteúdo oculto temporariamente");
  if (event.type === "narration.published") publicPayload.chapters =
    mapChapters(publicPayload.chapters, () => "Conteúdo oculto temporariamente");
  return { ...event, public_summary_pt: "Conteúdo oculto temporariamente", public: publicPayload };
}

export function embargoPublicEvent<T extends ArenaEvent>(event: T, disclosedAttackIds: ReadonlySet<string>): T {
  const attackId = typeof event.public.attack_id === "string" ? event.public.attack_id : undefined;
  if (!event.type.startsWith("attack.") || !attackId || disclosedAttackIds.has(attackId)) return event;
  if (event.type === "attack.attempted") return { ...event,
    public_summary_pt: safeFallback(event.area), public: { ...event.public, technique_label: "Técnica em análise" } };
  if (event.type === "attack.succeeded") return { ...event,
    public_summary_pt: safeFallback(event.area), public: { ...event.public,
      weakness_class_label: "Vulnerabilidade em correção", invariant_label_pt: "Detalhe reservado" } };
  return event;
}
