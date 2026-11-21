import { createHash, randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";
import { DatabaseSync } from "node:sqlite";
import { resolve } from "node:path";
import { runPatchCi, type PatchCiResult } from "./patch-ci.ts";
import type { PatchScope } from "../../world/src/patch-guard.ts";
import { watchDurationMs } from "./rollback-watch.ts";

interface RunRow { id: string; base_sha: string; candidate_sha: string; diff_sha256: string;
  task_id: string; state: string; reviewer_id: string | null; merged_at: string | null;
  ci_result_json: string; }
export class PatchCiFailure extends Error {
  readonly result: PatchCiResult;
  constructor(result: PatchCiResult) { super("PATCH_CI_FAILED"); this.result = result; }
}
function git(root: string, args: string[]): string {
  return execFileSync("git", ["-c", "core.hooksPath=/dev/null", ...args], { cwd: root,
    encoding: "utf8", maxBuffer: 4 * 1024 * 1024 }).trim();
}
function digest(value: string): string { return createHash("sha256").update(value).digest("hex"); }

export class PatchPipeline {
  readonly db: DatabaseSync;
  readonly repoRoot: string;
  constructor(db: DatabaseSync, repoRoot: string) {
    this.db = db; this.repoRoot = resolve(repoRoot);
    db.exec(`CREATE TABLE IF NOT EXISTS patch_ci_runs (
      id TEXT PRIMARY KEY, task_id TEXT NOT NULL, base_sha TEXT NOT NULL,
      candidate_sha TEXT NOT NULL UNIQUE, diff_sha256 TEXT NOT NULL,
      state TEXT NOT NULL CHECK(state IN ('ci_passed','approved','merged','rolled_back')),
      reviewer_id TEXT, merged_at TEXT, created_at TEXT NOT NULL,
      ci_result_json TEXT NOT NULL
    );`);
    const columns = db.prepare("PRAGMA table_info(patch_ci_runs)").all() as { name: string }[];
    if (!columns.some((column) => column.name === "ci_result_json"))
      db.exec("ALTER TABLE patch_ci_runs ADD COLUMN ci_result_json TEXT NOT NULL DEFAULT '{}'");
  }
  private row(runId: string): RunRow {
    const row = this.db.prepare("SELECT * FROM patch_ci_runs WHERE id=?").get(runId) as RunRow | undefined;
    if (!row) throw new Error("PATCH_RUN_NOT_FOUND");
    return row;
  }
  async evaluate(input: { taskId: string; diff: string; scope: PatchScope;
    redFirstTestSource: string }): Promise<{ runId: string; result: PatchCiResult }> {
    const result = await runPatchCi({ repoRoot: this.repoRoot, diff: input.diff, scope: input.scope,
      redFirstTestSource: input.redFirstTestSource, retainCandidate: true });
    if (!result.readyForReview || !result.headSha) throw new PatchCiFailure(result);
    const runId = `ci_${randomUUID()}`;
    this.db.prepare("INSERT INTO patch_ci_runs VALUES (?,?,?,?,?,'ci_passed',NULL,NULL,?,?)")
      .run(runId, input.taskId, result.baseSha, result.headSha, digest(input.diff),
        new Date().toISOString(), JSON.stringify(result));
    return { runId, result };
  }
  approve(input: { runId: string; taskId: string; headSha: string; reviewerId: string }): void {
    const row = this.row(input.runId);
    if (row.state !== "ci_passed" || row.task_id !== input.taskId || row.candidate_sha !== input.headSha ||
      !input.reviewerId) throw new Error("PATCH_REVIEW_MISMATCH");
    this.db.prepare("UPDATE patch_ci_runs SET state='approved',reviewer_id=? WHERE id=?")
      .run(input.reviewerId, input.runId);
  }
  merge(runId: string): string {
    const row = this.row(runId);
    if (row.state !== "approved" && row.state !== "merged" || !row.reviewer_id)
      throw new Error("PATCH_NOT_APPROVED");
    if (git(this.repoRoot, ["status", "--porcelain", "--untracked-files=no"]))
      throw new Error("PATCH_REPO_DIRTY");
    const retained = git(this.repoRoot, ["rev-parse", `refs/banco-vivo/ci/${row.candidate_sha}`]);
    if (retained !== row.candidate_sha || git(this.repoRoot, ["rev-parse", `${retained}^`]) !== row.base_sha)
      throw new Error("PATCH_CANDIDATE_MISMATCH");
    const head = git(this.repoRoot, ["rev-parse", "HEAD"]);
    if (head !== row.base_sha && head !== retained) throw new Error("PATCH_BASE_CHANGED");
    if (row.state === "merged" && head !== retained) throw new Error("PATCH_MERGE_MISMATCH");
    if (head === row.base_sha)
      git(this.repoRoot, ["merge", "--ff-only", "--no-edit", retained]);
    if (git(this.repoRoot, ["rev-parse", "HEAD"]) !== retained)
      throw new Error("PATCH_MERGE_MISMATCH");
    if (row.state !== "merged")
      this.db.prepare("UPDATE patch_ci_runs SET state='merged',merged_at=? WHERE id=?")
        .run(new Date().toISOString(), runId);
    return retained;
  }
  rollback(runId: string, reason: string, watchStartedAt?: Date): string {
    const row = this.row(runId);
    const windowStart = watchStartedAt?.getTime() ?? Date.parse(row.merged_at ?? "");
    // Allow the monitor's final checkpoint to finish after the watch window.
    if (row.state !== "merged" || !row.merged_at || !Number.isFinite(windowStart) ||
      (watchStartedAt && windowStart < Date.parse(row.merged_at) - 5_000) ||
      Date.now() - windowStart > watchDurationMs() + 30_000)
      throw new Error("PATCH_ROLLBACK_WINDOW_CLOSED");
    if (reason.trim().length < 3) throw new Error("PATCH_ROLLBACK_REASON_REQUIRED");
    if (git(this.repoRoot, ["rev-parse", "HEAD"]) !== row.candidate_sha ||
      git(this.repoRoot, ["status", "--porcelain", "--untracked-files=no"]))
      throw new Error("PATCH_ROLLBACK_STATE_CHANGED");
    git(this.repoRoot, ["-c", "user.name=Banco Vivo Runtime", "-c",
      "user.email=runtime@banco-vivo.invalid", "revert", "--no-edit", row.candidate_sha]);
    const revertSha = git(this.repoRoot, ["rev-parse", "HEAD"]);
    this.db.prepare("UPDATE patch_ci_runs SET state='rolled_back' WHERE id=?").run(runId);
    return revertSha;
  }
  state(runId: string): RunRow["state"] { return this.row(runId).state; }
  details(runId: string): { runId: string; taskId: string; state: string; baseSha: string;
    headSha: string; reviewerId: string | null; result: PatchCiResult } {
    const row = this.row(runId);
    return { runId: row.id, taskId: row.task_id, state: row.state, baseSha: row.base_sha,
      headSha: row.candidate_sha, reviewerId: row.reviewer_id,
      result: JSON.parse(row.ci_result_json) as PatchCiResult };
  }
}
