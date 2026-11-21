import type { Role } from "../../contracts/src/index.ts";
import { PRECONDITIONS } from "../../contracts/src/preconditions.ts";
import { PROMPTS } from "./prompts.ts";

type PromptRole = Exclude<Role, "sentinel" | "historian" | "scout" | "intruder" | "exploiter">;
const BLUE = new Set<PromptRole>(["investigator", "forensic_mapper", "root_cause_analyst",
  "architect", "engineer", "reviewer", "damage_assessor", "restorer", "hardening"]);
const reference = [
  "STATIC REFERENCE (pattern-level only)",
  "Controlled preconditions: " + PRECONDITIONS.join(", "),
  "Compact tool output keys: ok=success, s=HTTP status, c=code, b=filtered body, ms=elapsed milliseconds, n=remaining quotas.",
].join("\n");

export function systemForRole(role: Exclude<Role, "sentinel">): [string, string] {
  if (BLUE.has(role as PromptRole)) return [PROMPTS.blue, `${PROMPTS[role as PromptRole]}\n\n${reference}`];
  if (role === "postmortem") return [PROMPTS.support, PROMPTS.postmortem];
  if (role === "product" || role === "narrator")
    return [PROMPTS.support, `${PROMPTS[role as PromptRole]}\n\n${reference}`];
  throw new Error("PROMPT_UNKNOWN_ROLE");
}

export function sanitizeDossier(value: unknown, depth = 0): unknown {
  if (depth > 8) return "[truncated]";
  if (typeof value === "string") return value.slice(0, 2000)
    .replace(/[\u0000-\u001f\u007f]/g, " ")
    .replace(/<[^>]*>/g, " ")
    .replace(/```/g, "` ` `")
    .replace(/\[(?:INST|\/INST)\]/gi, " ")
    .replace(/\b(?:system|developer|assistant|user)\s*:/gi, "[untrusted label]:");
  if (Array.isArray(value)) return value.slice(0, 100).map((item) => sanitizeDossier(item, depth + 1));
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value)
    .slice(0, 100).map(([key, item]) => [key, sanitizeDossier(item, depth + 1)]));
  return value;
}

export function agentPrompt(role: Exclude<Role, "sentinel">, roundContext: unknown, dossier: unknown): {
  system: [string, string]; snapshot: unknown; dossier: unknown } {
  return { system: systemForRole(role), snapshot: sanitizeDossier(roundContext),
    dossier: sanitizeDossier(dossier) };
}
