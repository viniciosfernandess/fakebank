import { execFileSync, spawn } from "node:child_process";
import { mkdtempSync, readdirSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { inspectPatch, type PatchInspection, type PatchScope } from "../../world/src/patch-guard.ts";

const WORLD_TESTS = new Set(["advanced-sentinels", "auth", "bank", "cards", "cashback", "data-sharing", "decoys",
  "dynamic-limits", "fees", "flash-loan", "gateway", "honest", "loans", "money", "proximity-pix",
  "scheduled-pix", "sentinels", "simulator", "temporary-card", "twin-api"]);
export interface CiStep { ok: boolean; exitCode: number; output: string; durationMs: number; }
export interface PatchCiResult { baseSha: string; headSha: string | null; inspection: PatchInspection;
  typecheck: CiStep; worldTests: CiStep | null; redFirst: "missing" | "failed_before" | "failed_after" | "pass";
  redFirstBefore?: CiStep; redFirstAfter?: CiStep; readyForReview: boolean; }
function git(cwd: string, args: string[]): string {
  return execFileSync("git", ["-c", "core.hooksPath=/dev/null", ...args], { cwd,
    encoding: "utf8", maxBuffer: 8 * 1024 * 1024 }).trim();
}
function command(cwd: string, args: string[], timeoutMs: number): Promise<CiStep> {
  const started = Date.now();
  return new Promise((resolve) => {
    const child = spawn(process.execPath, args, { cwd: realpathSync(cwd), env: { PATH: process.env.PATH ?? "", NODE_ENV: "test",
      TMPDIR: realpathSync(tmpdir()) },
      stdio: ["ignore", "pipe", "pipe"] });
    let output = "";
    const collect = (chunk: Buffer) => { output = (output + chunk.toString()).slice(-6000); };
    child.stdout.on("data", collect); child.stderr.on("data", collect);
    const timer = setTimeout(() => child.kill("SIGKILL"), timeoutMs);
    child.once("close", (code) => {
      clearTimeout(timer);
      resolve({ ok: code === 0, exitCode: code ?? -1, output, durationMs: Date.now() - started });
    });
  });
}
async function suite(cwd: string, baseArgs: string[], files: string[], timeoutMs: number): Promise<CiStep> {
  let durationMs = 0;
  let output = "";
  for (const file of files) {
    const step = await command(cwd, [...baseArgs, file], timeoutMs);
    durationMs += step.durationMs;
    output = (output + `\n${file}:\n` + step.output).slice(-6000);
    if (!step.ok) return { ok: false, exitCode: step.exitCode, output, durationMs };
  }
  return { ok: true, exitCode: 0, output, durationMs };
}
function permissionArgs(worktree: string, nodeModules: string, sourceRoots: string[]): string[] {
  return ["--permission", ...sourceRoots.map((path) => `--allow-fs-read=${join(realpathSync(worktree), path)}`),
    `--allow-fs-read=${realpathSync(nodeModules)}`,
    `--allow-fs-read=${nodeModules}`,
    `--allow-fs-read=${join(realpathSync(worktree), "node_modules")}`,
    `--allow-fs-write=${realpathSync(tmpdir())}`,
    "--disable-warning=ExperimentalWarning", "--experimental-strip-types"];
}

export async function runPatchCi(input: { repoRoot: string; diff: string; scope: PatchScope;
  redFirstTestSource?: string; retainCandidate?: boolean }): Promise<PatchCiResult> {
  const inspection = inspectPatch(input.diff, input.scope);
  const root = realpathSync(resolve(input.repoRoot));
  const baseSha = git(root, ["rev-parse", "HEAD"]);
  const worktree = realpathSync(mkdtempSync(join(tmpdir(), "banco-vivo-ci-")));
  let headSha: string | null = null;
  let redFirst: PatchCiResult["redFirst"] = "missing";
  let redFirstBefore: CiStep | undefined;
  let redFirstAfter: CiStep | undefined;
  let typecheck: CiStep = { ok: false, exitCode: -1, output: "not_run", durationMs: 0 };
  let worldTests: CiStep | null = null;
  try {
    git(worktree, ["clone", "--local", "--no-hardlinks", "--quiet", root, worktree]);
    if (git(worktree, ["rev-parse", "HEAD"]) !== baseSha) throw new Error("CI_HEAD_CHANGED");
    const nodeModules = join(root, "node_modules");
    symlinkSync(realpathSync(nodeModules), join(worktree, "node_modules"), "dir");
    const worldPermissions = permissionArgs(worktree, nodeModules,
      ["apps/world/src", "apps/orchestrator/src", "packages", "tests", "fixtures", "rules", "apps/web/public", "package.json"]);
    if (input.redFirstTestSource !== undefined) {
      if (Buffer.byteLength(input.redFirstTestSource) > 16_384) throw new Error("CI_PROOF_TOO_LARGE");
      const proof = join(worktree, "tests", "red-first-proof.test.mjs");
      writeFileSync(proof, input.redFirstTestSource);
      const before = await command(join(worktree, "tests"), [...worldPermissions,
        "red-first-proof.test.mjs"], 30_000);
      redFirstBefore = before;
      if (before.ok) redFirst = "failed_before";
    }
    const patch = join(worktree, ".candidate.patch");
    writeFileSync(patch, input.diff);
    git(worktree, ["apply", "--check", patch]);
    git(worktree, ["apply", patch]);
    git(worktree, ["diff", "--check"]);
    git(worktree, ["add", "--", ...inspection.paths]);
    git(worktree, ["-c", "user.name=Banco Vivo CI", "-c", "user.email=ci@banco-vivo.invalid",
      "commit", "--quiet", "-m", "Candidate patch"]);
    headSha = git(worktree, ["rev-parse", "HEAD"]);
    const typePermissions = permissionArgs(worktree, nodeModules, ["."]);
    typecheck = await command(worktree, [...typePermissions, realpathSync(join(nodeModules, "typescript/bin/tsc")),
      "--noEmit", "-p", join(realpathSync(worktree), "tsconfig.json")], 60_000);
    if (!typecheck.ok) return { baseSha, headSha, inspection, typecheck, worldTests, redFirst,
      ...(redFirstBefore ? { redFirstBefore } : {}), readyForReview: false };
    if (input.redFirstTestSource !== undefined && redFirst !== "failed_before") {
      const after = await command(join(worktree, "tests"), [...worldPermissions,
        "red-first-proof.test.mjs"], 30_000);
      redFirstAfter = after;
      redFirst = after.ok ? "pass" : "failed_after";
    }
    const tests = readdirSync(join(worktree, "tests")).filter((name) =>
      name.endsWith(".test.mjs") && WORLD_TESTS.has(name.slice(0, -9))).sort()
      .map((name) => name);
    worldTests = await suite(join(worktree, "tests"), [...worldPermissions,
      "--test-skip-pattern=^(?:W[0-9][0-9]|F[1-7])"], tests, 240_000);
    const readyForReview = typecheck.ok && worldTests.ok && redFirst === "pass";
    if (readyForReview && input.retainCandidate) git(root, ["fetch", "--quiet", worktree,
      `HEAD:refs/banco-vivo/ci/${headSha}`]);
    return { baseSha, headSha, inspection, typecheck, worldTests, redFirst,
      ...(redFirstBefore ? { redFirstBefore } : {}), ...(redFirstAfter ? { redFirstAfter } : {}),
      readyForReview };
  } finally { rmSync(worktree, { recursive: true, force: true }); }
}
