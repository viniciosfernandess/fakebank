import type { Area } from "../../../packages/contracts/src/index.ts";

export class PatchGuardError extends Error {
  readonly code: string;
  constructor(code: string) { super(code); this.code = code; }
}
export interface PatchScope { area: Area; featureId?: string; maxFiles?: number; maxChangedLines?: number; }
export interface PatchInspection { paths: string[]; files: number; changedLines: number; kind: "code" | "rule" | "mixed"; }
const AREA_FILES: Record<Area, ReadonlySet<string>> = {
  auth: new Set(["apps/world/src/auth.ts"]),
  accounts: new Set(["apps/world/src/accounts.ts", "apps/world/src/account-policy.ts", "apps/world/src/dynamic-limits.ts"]),
  pix: new Set(["apps/world/src/scheduled-pix.ts", "apps/world/src/proximity-pix.ts", "apps/world/src/pix-policy.ts"]),
  cards: new Set(["apps/world/src/cards.ts"]),
  loans: new Set(["apps/world/src/loans.ts"]),
  api_gateway: new Set(["apps/world/src/gateway.ts", "apps/world/src/data-sharing.ts"]),
  ledger: new Set(["apps/world/src/fees.ts", "apps/world/src/cashback.ts"]),
};
const PROTECTED_PREFIXES = ["tests/", "packages/", "apps/server/", "apps/web/", "docs/", "fixtures/",
  "scripts/", ".github/", ".ci/", "sandbox/", "harness/", "node_modules/"];
const PROTECTED_FILES = new Set(["apps/world/src/bank.ts", "apps/world/src/sentinels.ts",
  "apps/world/src/seed.ts", "apps/world/src/api.ts", "apps/world/src/features.ts",
  "apps/world/src/catalog.ts", "apps/world/src/clock.ts", "apps/world/src/simulator.ts",
  "package.json", "pnpm-lock.yaml", "pnpm-workspace.yaml", "tsconfig.json", "README.md"]);
export function editablePaths(scope: PatchScope): string[] {
  return [...AREA_FILES[scope.area], ...(scope.featureId ? [`lab/${scope.featureId}/`] : [])].sort();
}
function validatePath(path: string, scope: PatchScope): "code" | "rule" {
  if (!path || path.startsWith("/") || path.includes("\\") || path.includes("\0") ||
    path.split("/").some((part) => part === "" || part === "." || part === ".."))
    throw new PatchGuardError("PATCH_INVALID_PATH");
  if (PROTECTED_FILES.has(path) || PROTECTED_PREFIXES.some((prefix) => path.startsWith(prefix)))
    throw new PatchGuardError("PATCH_PROTECTED_PATH");
  if (path === `rules/${scope.area}/limits.json`) throw new PatchGuardError("PATCH_PROTECTED_PATH");
  if (path.startsWith(`rules/${scope.area}/`) && path.endsWith(
    scope.area === "pix" || scope.area === "cards" ? ".json" : ".yaml")) return "rule";
  if (scope.featureId && path.startsWith(`lab/${scope.featureId}/`) && path.endsWith(".ts")) return "code";
  if (AREA_FILES[scope.area].has(path)) return "code";
  throw new PatchGuardError("PATCH_OUT_OF_SCOPE");
}
export function isEditablePath(path: string, scope: PatchScope): boolean {
  try { validatePath(path, scope); return true; } catch { return false; }
}
export function inspectPatch(diff: string, scope: PatchScope): PatchInspection {
  if (!diff || Buffer.byteLength(diff, "utf8") > 64 * 1024 || diff.includes("\r"))
    throw new PatchGuardError("PATCH_INVALID_FORMAT");
  const lines = diff.split("\n");
  const paths: string[] = [];
  const kinds = new Set<"code" | "rule">();
  let current: string | undefined;
  let oldHeader = false; let newHeader = false; let hunks = 0; let changedLines = 0;
  const finish = (): void => {
    if (current && (!oldHeader || !newHeader || !hunks)) throw new PatchGuardError("PATCH_INVALID_FORMAT");
  };
  for (const line of lines) {
    if (line.startsWith("diff --git ")) {
      finish();
      const match = /^diff --git a\/([^\s]+) b\/([^\s]+)$/.exec(line);
      const path = match?.[1];
      if (!path || path !== match?.[2]) throw new PatchGuardError("PATCH_RENAME_DENIED");
      current = path;
      if (paths.includes(current)) throw new PatchGuardError("PATCH_DUPLICATE_PATH");
      kinds.add(validatePath(current, scope));
      paths.push(current);
      oldHeader = false; newHeader = false; hunks = 0;
      continue;
    }
    if (!current) {
      if (line !== "") throw new PatchGuardError("PATCH_INVALID_FORMAT");
      continue;
    }
    if (/^(GIT binary patch|Binary files |old mode |new mode |deleted file mode |new file mode 120000|rename |copy |similarity index |Submodule )/.test(line))
      throw new PatchGuardError("PATCH_UNSUPPORTED_CHANGE");
    if (line.startsWith("--- ")) {
      if (line !== `--- a/${current}` && line !== "--- /dev/null") throw new PatchGuardError("PATCH_INVALID_FORMAT");
      oldHeader = true; continue;
    }
    if (line.startsWith("+++ ")) {
      if (line !== `+++ b/${current}`) throw new PatchGuardError("PATCH_INVALID_FORMAT");
      newHeader = true; continue;
    }
    if (line.startsWith("@@ ")) {
      if (!oldHeader || !newHeader || !/^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@/.test(line))
        throw new PatchGuardError("PATCH_INVALID_FORMAT");
      hunks++; continue;
    }
    if (line.startsWith("+") || line.startsWith("-")) {
      if (!hunks) throw new PatchGuardError("PATCH_INVALID_FORMAT");
      changedLines++; continue;
    }
    if (line.startsWith(" ") || line === "\\ No newline at end of file" || line === "" || line.startsWith("index ") || line.startsWith("new file mode 100644"))
      continue;
    throw new PatchGuardError("PATCH_INVALID_FORMAT");
  }
  finish();
  if (!paths.length || changedLines === 0) throw new PatchGuardError("PATCH_INVALID_FORMAT");
  if (paths.length > (scope.maxFiles ?? 4) || changedLines > (scope.maxChangedLines ?? 120))
    throw new PatchGuardError("PATCH_SIZE_LIMIT");
  return { paths, files: paths.length, changedLines, kind: kinds.size === 2 ? "mixed" : kinds.has("rule") ? "rule" : "code" };
}
