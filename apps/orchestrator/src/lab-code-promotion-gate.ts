import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, realpathSync,
  rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import type { PatchPipeline } from "./patch-pipeline.ts";

const git = (root: string, args: string[]): string =>
  execFileSync("git", ["-c", "core.hooksPath=/dev/null", ...args], {
    cwd: root, encoding: "utf8", maxBuffer: 4 * 1024 * 1024 }).trim();

/** Full bank gate on the exact reviewed commit, before touching the running lab. */
export async function runLabCodePromotionGate(input: {
  repoRoot: string; ciRunId: string; pipeline: PatchPipeline;
}): Promise<{ tests: number; outputSha256: string }> {
  const root = realpathSync(resolve(input.repoRoot));
  const dataDir = dirname(root);
  if (basename(root) !== "code-checkout" ||
    readFileSync(join(dataDir, "fault-lab.marker"), "utf8") !==
      "banco-vivo-fault-lab-v1\n" ||
    !existsSync(join(root, ".lab-code-source")))
    throw new Error("LAB_CODE_PROMOTION_SCOPE_INVALID");
  const details = input.pipeline.details(input.ciRunId);
  if (details.state !== "approved" ||
    git(root, ["rev-parse", "HEAD"]) !== details.baseSha ||
    git(root, ["status", "--porcelain"]))
    throw new Error("LAB_CODE_PROMOTION_CANDIDATE_CHANGED");
  const candidateRef = `refs/banco-vivo/ci/${details.headSha}`;
  if (git(root, ["rev-parse", candidateRef]) !== details.headSha)
    throw new Error("LAB_CODE_PROMOTION_REF_MISSING");
  const clone = mkdtempSync(join(tmpdir(), "banco-vivo-promotion-gate-"));
  try {
    git(clone, ["clone", "--local", "--no-hardlinks", "--quiet", root, clone]);
    git(clone, ["fetch", "--quiet", root, candidateRef]);
    git(clone, ["checkout", "--quiet", "--detach", "FETCH_HEAD"]);
    if (git(clone, ["rev-parse", "HEAD"]) !== details.headSha)
      throw new Error("LAB_CODE_PROMOTION_HEAD_MISMATCH");
    symlinkSync(join(root, "node_modules"), join(clone, "node_modules"), "dir");
    execFileSync(join(clone, "node_modules/.bin/vite"), ["build"], {
      cwd: join(clone, "apps/web"), encoding: "utf8",
      maxBuffer: 4 * 1024 * 1024,
      env: { PATH: process.env.PATH ?? "", HOME: process.env.HOME ?? "",
        TMPDIR: process.env.TMPDIR ?? tmpdir(), NODE_ENV: "test" },
      timeout: 120_000 });
    const output = await new Promise<{ code: number | null; text: string;
      sha256: string }>((done) => {
      const child = spawn(process.execPath, ["--disable-warning=ExperimentalWarning",
        "scripts/verify-local-bank-tests.mjs"], {
        cwd: clone, env: { PATH: process.env.PATH ?? "",
          HOME: process.env.HOME ?? "", TMPDIR: process.env.TMPDIR ?? tmpdir(),
          NODE_ENV: "test" }, stdio: ["ignore", "pipe", "pipe"],
        detached: process.platform !== "win32" });
      let text = "";
      const digest = createHash("sha256");
      const collect = (chunk: Buffer) => {
        digest.update(chunk);
        text += chunk.toString();
      };
      child.stdout.on("data", collect);
      child.stderr.on("data", collect);
      const killGroup = () => {
        if (child.pid && process.platform !== "win32") {
          try { process.kill(-child.pid, "SIGKILL"); } catch { /* Already exited. */ }
        } else child.kill("SIGKILL");
      };
      const timer = setTimeout(killGroup, 900_000);
      let settled = false;
      const finish = (code: number | null) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        done({ code, text, sha256: digest.digest("hex") });
      };
      child.once("close", finish);
      child.once("exit", () => {
        // A nested test can inherit the output pipe after its parent exits.
        // A still-open pipe is an incomplete gate, even if a summary was printed.
        setTimeout(() => {
          if (settled) return;
          killGroup();
          finish(-1);
        }, 5_000).unref();
      });
      child.once("error", () => finish(-1));
    });
    const tests = Number(/ℹ pass (\d+)/.exec(output.text)?.[1]);
    if (output.code !== 0 || !Number.isSafeInteger(tests) || tests < 1_000 ||
      !/ℹ fail 0(?:\r?\n|$)/.test(output.text) ||
      !/ℹ cancelled 0(?:\r?\n|$)/.test(output.text))
      throw new Error(`LAB_CODE_PROMOTION_BANK_GATE_FAILED:${output.code}:${tests}:` +
        output.text.split("\n").filter((line) => line.startsWith("✖ ") ||
          line.startsWith("ℹ fail ")).join(" | ").slice(0, 3000));
    return { tests, outputSha256: output.sha256 };
  } finally { rmSync(clone, { recursive: true, force: true }); }
}
