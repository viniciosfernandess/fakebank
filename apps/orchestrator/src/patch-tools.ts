import { lstatSync, readFileSync, readdirSync, realpathSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { resolve, sep } from "node:path";
import { z } from "zod";
import type { AgentTool } from "./agent-loop.ts";
import { PatchCiFailure, PatchPipeline } from "./patch-pipeline.ts";
import { editablePaths, inspectPatch, isEditablePath, type PatchScope } from "../../world/src/patch-guard.ts";

const id = z.string().min(3).max(128);
const readInput = z.strictObject({ path: z.string().min(1).max(256),
  start_line: z.number().int().min(1).max(20_000).optional(),
  max_lines: z.number().int().min(1).max(150).optional() });
const searchInput = z.strictObject({ query: z.string().min(2).max(120) });
const runInput = z.strictObject({ run_id: id });
const applyInput = z.strictObject({ task_id: id, diff: z.string().min(1).max(65_536) });
const reviewInput = z.strictObject({ run_id: id, head_sha: z.string().regex(/^[0-9a-f]{40}$/),
  decision: z.enum(["approve", "reject"]), reason: z.string().max(500) });
// Leave room for result metadata within the role broker's transport limit.
const sourceResultLimit = 7_500;
export interface PatchToolContext { repoRoot: string; taskId: string; scope: PatchScope; pipeline: PatchPipeline;
  redFirstTestSource: string; reproductionSymptoms: string[]; regressionIds: string[];
  reviewerId?: string; allowedPaths?: string[]; readOnlyPaths?: string[]; }

function tool<T>(name: string, kind: AgentTool["kind"], schema: z.ZodType<T>, description: string,
  execute: (input: T) => Promise<unknown> | unknown, timeoutMs?: number): AgentTool {
  return { name, kind, schema, description, execute: async (raw) => execute(schema.parse(raw)),
    ...(timeoutMs ? { timeoutMs: () => timeoutMs } : {}) };
}
function allowedFile(context: PatchToolContext, path: string): string {
  if (path.startsWith("/") || path.includes("\\") || path.includes("\0") ||
    path.split("/").some((part) => !part || part === "." || part === ".."))
    throw new Error("PATCH_READ_OUT_OF_SCOPE");
  const editable = isEditablePath(path, context.scope) &&
    (!context.allowedPaths || context.allowedPaths.includes(path));
  if (!editable && !context.readOnlyPaths?.includes(path))
    throw new Error("PATCH_READ_OUT_OF_SCOPE");
  const root = realpathSync(context.repoRoot);
  const file = resolve(root, path);
  if (!file.startsWith(`${root}${sep}`) || !lstatSync(file).isFile() ||
    realpathSync(file) !== file) throw new Error("PATCH_READ_OUT_OF_SCOPE");
  return file;
}
function commonTools(context: PatchToolContext): AgentTool[] {
  const ruleDir = `rules/${context.scope.area}`;
  let rulePaths: string[] = [];
  try { rulePaths = readdirSync(resolve(context.repoRoot, ruleDir), { withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name !== "limits.json" && entry.name.endsWith(
      context.scope.area === "pix" || context.scope.area === "cards" ? ".json" : ".yaml"))
    .slice(0, 30).map((entry) => `${ruleDir}/${entry.name}`); }
  catch { /* Areas without rule files still support source search. */ }
  return [
    tool("repo.read", "code", readInput,
      "Read a scoped source range. Search for a symbol first, then pass start_line and max_lines. Use next_line to continue when a result reaches its size limit.",
      ({ path, start_line = 1, max_lines = 120 }) => {
        const lines = readFileSync(allowedFile(context, path), "utf8").split("\n");
        const selected: string[] = [];
        let encodedSize = 0;
        let lineTruncated = false;
        for (const line of lines.slice(start_line - 1, start_line - 1 + max_lines)) {
          encodedSize += JSON.stringify(line).length;
          if (encodedSize > sourceResultLimit) {
            if (!selected.length) {
              selected.push(line.slice(0, 1_000));
              lineTruncated = true;
            }
            break;
          }
          selected.push(line);
        }
        const nextLine = start_line + selected.length;
        return { path, start_line, total_lines: lines.length,
          next_line: nextLine <= lines.length ? nextLine : null,
          line_truncated: lineTruncated, content: selected.join("\n") };
      }),
    tool("repo.search", "code", searchInput, "Find a literal string in editable files of this area.",
      ({ query }) => {
        const matches: { path: string; line: number; text: string }[] = [];
        let encodedSize = 2;
        const paths = [...new Set([...(context.allowedPaths ??
          [...editablePaths(context.scope), ...rulePaths]),
          ...(context.readOnlyPaths ?? [])])];
        for (const path of paths.filter((item) => !item.endsWith("/"))) {
          let lines: string[];
          try { lines = readFileSync(allowedFile(context, path), "utf8").split("\n"); }
          catch { continue; }
          for (const [index, line] of lines.entries()) {
            if (!line.includes(query)) continue;
            const match = { path, line: index + 1, text: line.slice(0, 180) };
            encodedSize += JSON.stringify(match).length + 1;
            if (encodedSize > sourceResultLimit) return matches;
            matches.push(match);
            if (matches.length >= 50) return matches;
          }
        }
        return matches;
      }),
  ];
}

export function createEngineerTools(context: PatchToolContext): AgentTool[] {
  return [...commonTools(context),
    tool("tests.reproduce", "ci", z.strictObject({ test_id: id }),
      "Read only bank-side symptoms of the verified breach; attacker steps remain private.",
      ({ test_id }) => {
        if (!context.regressionIds.includes(test_id)) throw new Error("PATCH_REGRESSION_SCOPE");
        return { violated_invariant: context.reproductionSymptoms[0] ?? "Unspecified invariant",
          bank_side_symptoms: context.reproductionSymptoms.slice(1, 6) };
      }),
    tool("repo.apply_patch", "code", applyInput,
      "Apply a standard unified git diff in isolated CI: diff --git, --- a/path, +++ b/path, and @@ hunk headers. Do not use the *** Begin Patch format. Return its exact run id and candidate commit.",
      async ({ task_id, diff }) => {
        if (task_id !== context.taskId) throw new Error("PATCH_TASK_SCOPE");
        if (context.allowedPaths && inspectPatch(diff, context.scope).paths.some((path) =>
          !context.allowedPaths!.includes(path))) throw new Error("PATCH_DESIGN_PATH_SCOPE");
        try {
          const { runId, result } = await context.pipeline.evaluate({ taskId: context.taskId, diff,
            scope: context.scope, redFirstTestSource: context.redFirstTestSource });
          return { ci_run_id: runId, head_sha: result.headSha, red_first: result.redFirst,
            typecheck: result.typecheck.ok, world_tests: result.worldTests?.ok,
            files: result.inspection.files, changed_lines: result.inspection.changedLines };
        } catch (error) {
          if (!(error instanceof PatchCiFailure)) throw error;
          return { ci_run_id: null, ready: false, red_first: error.result.redFirst,
            typecheck: error.result.typecheck.ok, world_tests: error.result.worldTests?.ok,
            failure_output: (error.result.redFirstAfter && !error.result.redFirstAfter.ok
              ? error.result.redFirstAfter.output : !error.result.typecheck.ok
                ? error.result.typecheck.output : error.result.worldTests?.output ?? "").slice(-1000) };
        }
      }, 360_000),
    tool("tests.run_targeted", "ci", runInput,
      "Read the targeted proof, typecheck and world-test result for one exact CI run.",
      ({ run_id }) => {
        const details = context.pipeline.details(run_id);
        if (details.taskId !== context.taskId) throw new Error("PATCH_TASK_SCOPE");
        return { head_sha: details.headSha, red_first: details.result.redFirst,
          typecheck: details.result.typecheck.ok, world_tests: details.result.worldTests?.ok };
      }),
  ];
}

export function createArchitectTools(context: PatchToolContext,
  caseHistory: () => Record<string, unknown>): AgentTool[] {
  return [...commonTools(context),
    tool("case.history", "investigate", z.strictObject({}),
      "Read the bounded incident history, previous designs, CI failures and reviews.",
      () => caseHistory())];
}

export function createReviewerTools(context: PatchToolContext & { reviewerId: string }): AgentTool[] {
  const details = (runId: string) => {
    const row = context.pipeline.details(runId);
    if (row.taskId !== context.taskId) throw new Error("PATCH_TASK_SCOPE");
    return row;
  };
  return [...commonTools(context),
    tool("repo.diff", "code", runInput, "Read the exact candidate diff from the tested commit.",
      ({ run_id }) => {
        const row = details(run_id);
        return { head_sha: row.headSha, diff: execFileSync("git", ["diff", "--no-ext-diff",
          row.baseSha, row.headSha, "--", ...row.result.inspection.paths],
        { cwd: context.repoRoot, encoding: "utf8", maxBuffer: 128 * 1024 }).slice(0, 65_536) };
      }),
    tool("diff.scope_check", "ci", runInput, "Inspect the path guard result for this candidate.",
      ({ run_id }) => ({ ...details(run_id).result.inspection, passed: true })),
    tool("tests.run_targeted", "ci", runInput, "Read typecheck and targeted proof results.",
      ({ run_id }) => {
        const row = details(run_id);
        return { red_first: row.result.redFirst, typecheck: row.result.typecheck.ok,
          world_tests: row.result.worldTests?.ok };
      }),
    tool("tests.run_regression", "ci", runInput,
      "Read the trusted breach proof result before and after the candidate patch.",
      ({ run_id }) => {
        const row = details(run_id);
        return { before_failed: row.result.redFirstBefore?.ok === false,
          after_passed: row.result.redFirstAfter?.ok === true, head_sha: row.headSha,
          proof_sha256: createHash("sha256").update(context.redFirstTestSource)
            .digest("hex"),
          before_output: row.result.redFirstBefore?.output?.slice(-1800) ?? null,
          after_output: row.result.redFirstAfter?.output?.slice(-600) ?? null };
      }),
    tool("tests.run_honest", "ci", runInput,
      "Read the honest-customer and world-test suite result from the exact candidate.",
      ({ run_id }) => {
        const row = details(run_id);
        return { pass: row.result.worldTests?.ok === true, head_sha: row.headSha,
          duration_ms: row.result.worldTests?.durationMs };
      }),
    tool("review.submit", "ci", reviewInput,
      "Approve only the exact green CI commit; rejection leaves the candidate unmerged.",
      ({ run_id, head_sha, decision, reason }) => {
        const row = details(run_id);
        if (row.headSha !== head_sha) throw new Error("PATCH_REVIEW_MISMATCH");
        if (decision === "reject") return { decision, reason, run_id };
        context.pipeline.approve({ runId: run_id, taskId: context.taskId,
          headSha: head_sha, reviewerId: context.reviewerId });
        return { decision, run_id, head_sha };
      }),
  ];
}
