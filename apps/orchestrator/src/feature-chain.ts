import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { z } from "zod";
import { launchBriefBody, parseDossierBody } from "../../../packages/contracts/src/dossiers.ts";
import type { EventStore } from "../../../packages/event-store/src/index.ts";
import { FEATURES } from "../../world/src/catalog.ts";
import type { AgentTool, AgentTransport } from "./agent-loop.ts";
import { agentExecutor, type AgentRuntime } from "./runtime/agent-runtime.ts";
import { stageAgentId } from "./runtime/stage-agent-id.ts";
import type { BudgetLedger } from "./budget.ts";
import type { StoredFeature } from "./schedule-store.ts";
import { compileProductJourneys, PRODUCT_VARIANT_FIELDS,
  type HonestJourneyScenario } from "./product-journey.ts";

const reviewBody = z.strictObject({ feature_id: z.string(), verdict: z.enum(["approve", "reject"]),
  run_id: z.string(), reason: z.string(), residual_risk: z.enum(["low", "medium", "high"]) });
const featureTestFiles: Record<string, string> = {
  pix_agendado_recorrente: "scheduled-pix.test.mjs",
  cartao_virtual_temporario: "temporary-card.test.mjs",
  emprestimo_relampago: "flash-loan.test.mjs",
  pix_aproximacao: "proximity-pix.test.mjs",
  cashback: "cashback.test.mjs",
  compartilhar_dados: "data-sharing.test.mjs",
  limite_dinamico: "dynamic-limits.test.mjs",
};
export interface FeatureCheck { runId: string; featureId: string; pass: boolean;
  tests: number; passed: number; failed: number; output: string; }
export async function runFeatureChecks(repoRoot: string, featureId: string,
  extraJourneys: HonestJourneyScenario[] = []): Promise<FeatureCheck> {
  const file = featureTestFiles[featureId];
  if (!file) throw new Error("FEATURE_UNKNOWN");
  const day = FEATURES.find((feature) => feature.id === featureId)?.day;
  if (!day) throw new Error("FEATURE_UNKNOWN");
  const root = realpathSync(repoRoot);
  const testDir = join(root, "tests");
  const generatedDir = mkdtempSync(join(tmpdir(), "banco-vivo-product-journeys-"));
  const generatedPath = join(realpathSync(generatedDir), "journeys.json");
  writeFileSync(generatedPath, JSON.stringify(extraJourneys));
  const baseArgs = ["--permission", ...["apps/world/src", "packages", "tests", "fixtures", "rules", "package.json"]
    .map((path) => `--allow-fs-read=${join(root, path)}`),
    `--allow-fs-read=${generatedPath}`,
    `--allow-fs-read=${join(root, "node_modules")}`,
    `--allow-fs-read=${realpathSync(join(root, "node_modules"))}`,
    `--allow-fs-write=${realpathSync(tmpdir())}`,
    "--disable-warning=ExperimentalWarning", "--experimental-strip-types"];
  const runFile = (name: string, skipPattern: string): Promise<{ code: number; text: string }> =>
    new Promise((resolve) => {
      const child = spawn(process.execPath, [...baseArgs, `--test-skip-pattern=${skipPattern}`, name], { cwd: testDir,
        env: { PATH: process.env.PATH ?? "", NODE_ENV: "test", TMPDIR: realpathSync(tmpdir()),
          BANCO_VIVO_EXTRA_JOURNEYS: generatedPath },
        stdio: ["ignore", "pipe", "pipe"] });
      let text = "";
      const collect = (chunk: Buffer) => { text = (text + chunk.toString()).slice(-12_000); };
      child.stdout.on("data", collect); child.stderr.on("data", collect);
      const timer = setTimeout(() => child.kill("SIGKILL"), 45_000);
      child.on("close", (code) => { clearTimeout(timer); resolve({ code: code ?? -1, text }); });
    });
  const otherLaunchDays = FEATURES.filter((feature) => feature.day !== day)
    .map((feature) => feature.day).join("");
  try {
    const outputs = [await runFile(file, "^W[0-9][0-9]"),
      await runFile("honest.test.mjs", `^(?:W[0-9][0-9]|F[1-7]|L[${otherLaunchDays}])`)];
    const count = (output: string, name: string): number => Number(
      new RegExp(`^(?:#|ℹ) ${name} (\\d+)$`, "m").exec(output)?.[1] ?? 0);
    const tests = outputs.reduce((sum, item) => sum + count(item.text, "tests"), 0);
    const passed = outputs.reduce((sum, item) => sum + count(item.text, "pass"), 0);
    const failed = outputs.reduce((sum, item) => sum + count(item.text, "fail"), 0);
    return { runId: `feature_ci_${randomUUID()}`, featureId,
      pass: outputs.every((item) => item.code === 0) &&
        count(outputs[0]!.text, "tests") > 0 &&
        count(outputs[1]!.text, "tests") >= 51 + extraJourneys.length &&
        passed === tests && failed === 0,
      tests, passed, failed, output: outputs.map((item) => item.text.slice(-500)).join("\n") };
  } finally { rmSync(generatedDir, { recursive: true, force: true }); }
}

export class FeatureChain {
  readonly events: EventStore;
  readonly budget: BudgetLedger | undefined;
  readonly transport: AgentTransport | undefined;
  readonly runtime: AgentRuntime | undefined;
  readonly repoRoot: string;
  readonly check: (featureId: string, journeys: HonestJourneyScenario[]) => Promise<FeatureCheck>;
  constructor(input: { events: EventStore; budget?: BudgetLedger; transport?: AgentTransport;
    repoRoot: string; runtime?: AgentRuntime;
    check?: (featureId: string, journeys: HonestJourneyScenario[]) => Promise<FeatureCheck> }) {
    this.events = input.events; this.budget = input.budget; this.transport = input.transport;
    this.runtime = input.runtime;
    this.repoRoot = input.repoRoot;
    this.check = input.check ?? ((featureId, journeys) => runFeatureChecks(this.repoRoot, featureId, journeys));
  }
  async run(slot: StoredFeature): Promise<{ approved: boolean; reason?: string;
    titlePt?: string; summaryPt?: string }> {
    const catalog = FEATURES.find((item) => item.id === slot.featureId && item.day === slot.day);
    if (!catalog) throw new Error("FEATURE_SLOT_INVALID");
    const availableJourneys = ["", "a", "b"].map((suffix) => {
      const id = `L${slot.day}${suffix}`;
      const scenario = JSON.parse(readFileSync(join(this.repoRoot, "tests", "honest",
        `${id}.scenario.json`), "utf8")) as { id: string; area: string;
          title: string; steps: unknown[] };
      if (scenario.id !== id || scenario.area !== catalog.area || !scenario.title ||
        !Array.isArray(scenario.steps) || scenario.steps.length === 0)
        throw new Error("FEATURE_JOURNEY_INVALID");
      return { id, title: scenario.title, editable_fields: scenario.steps.flatMap((step, index) => {
        if (!step || typeof step !== "object") return [];
        const entry = step as Record<string, unknown>;
        const target = entry.kind === "request" && entry.body && typeof entry.body === "object" ?
          entry.body as Record<string, unknown> :
          entry.kind === "harness" && entry.action === "recordVerifiedIncome" ? entry : {};
        return PRODUCT_VARIANT_FIELDS.filter((field) =>
          typeof target[field] === "number" || typeof target[field] === "string")
          .map((field) => ({ step_index: index, field, current_value: target[field] }));
      }) };
    });
    const runId = `product_${slot.day}`;
    this.budget?.openRun(runId, "product");
    const loop = agentExecutor(this.events, this.budget, this.runtime, this.transport);
    const productId = this.runtime ? stageAgentId(this.events, runId, "product", slot.featureId) :
      `product_${randomUUID()}`;
    const product = await loop.run({ runId, agentId: productId, role: "product",
      deadlineAt: Date.parse(slot.endsAt),
      goalPt: `Prepare the launch brief for ${slot.featureId}`,
      snapshot: { featureId: slot.featureId, day: slot.day, area: catalog.area },
      dossier: { featureId: slot.featureId, preauthored: true,
        availableJourneys,
        requirement: `Describe L${slot.day}, L${slot.day}a and L${slot.day}b, then propose one to three executable variants P${slot.day}a to P${slot.day}c. Each variant needs {base_id,step_index,field,value} from the editable fields above. Change one value to a plausible honest value; the harness will run it.`,
        variant_ids: ["a", "b", "c"].map((suffix) => `P${slot.day}${suffix}`) },
      dossierSchema: launchBriefBody,
      validateDossier: (body) => {
        try { parseDossierBody("product", body); }
        catch { return false; }
        if (body.feature_id !== slot.featureId) return false;
        try { compileProductJourneys(this.repoRoot, slot.day, catalog.area, body.honest_journeys); }
        catch { return false; }
        return true;
      }, tools: [], maxTurns: 3, maxTokens: 1600 });
    if (product.status !== "ok" || !product.data)
      return { approved: false, reason: `product_${product.status}` };
    if (product.data.launch_recommendation !== "launch")
      return { approved: false, reason: "product_hold" };
    const productJourneys = compileProductJourneys(this.repoRoot, slot.day, catalog.area,
      product.data.honest_journeys);
    let check: FeatureCheck | undefined;
    let approvedRunId: string | undefined;
    const tools: AgentTool[] = [
      { name: "tests.run_honest", kind: "ci", description: "Run the pre-authored feature and honest-customer tests.",
        schema: z.strictObject({ feature_id: z.literal(slot.featureId) }),
        execute: async () => {
          if (!check) {
            check = await this.check(slot.featureId, productJourneys);
            this.events.append({ round_id: null, ts: new Date().toISOString(),
              type: "regression.result", actor: { id: "feature-ci", role: "system" },
              area: catalog.area,
              public_summary_pt: check.pass ? "Recurso passou nos testes" : "Recurso falhou nos testes",
              public: { run_id: check.runId, suite: "honest", kind: "ci",
                pass: check.passed, fail: check.failed, total: check.tests },
              private: { feature_id: slot.featureId, output: check.output } });
          }
          return { run_id: check.runId, pass: check.pass, tests: check.tests,
            passed: check.passed, failed: check.failed, output: check.output };
        }, timeoutMs: () => 50_000, wallExtensionMs: () => 50_000 },
      { name: "review.submit", kind: "ci", description: "Approve only the passing feature test run.",
        schema: z.strictObject({ run_id: z.string(), decision: z.enum(["approve", "reject"]),
          reason: z.string().max(300) }),
        execute: async (raw) => {
          const input = raw as { run_id: string; decision: "approve" | "reject"; reason: string };
          if (!check || input.run_id !== check.runId) throw new Error("FEATURE_REVIEW_RUN_MISMATCH");
          if (input.decision === "approve") {
            if (!check.pass) throw new Error("FEATURE_TESTS_FAILED");
            approvedRunId = check.runId;
          }
          return { decision: input.decision, run_id: check.runId };
        } },
    ];
    const reviewer = await loop.run({ runId, agentId: `feature_reviewer_${randomUUID()}`,
      deadlineAt: Date.parse(slot.endsAt),
      role: "reviewer", goalPt: `Review clean launch of ${slot.featureId}`,
      system: ["You review only the fictional Banco Vivo feature launch in an isolated synthetic bank.",
        "Run tests.run_honest, inspect the result, then call review.submit. Approve only if every test passes. End with submit_dossier. Do not edit code or invent evidence."],
      snapshot: { featureId: slot.featureId, day: slot.day, area: catalog.area },
      dossier: { brief: product.data, preauthoredFeature: true }, dossierSchema: reviewBody,
      validateDossier: (body) => body.feature_id === slot.featureId &&
        (body.verdict === "reject" || Boolean(approvedRunId && body.run_id === approvedRunId &&
          body.residual_risk !== "high")), tools, maxTurns: 4, maxTokens: 1200 });
    if (reviewer.status !== "ok" || !reviewer.data)
      return { approved: false, reason: `reviewer_${reviewer.status}` };
    if (reviewer.data.verdict !== "approve") return { approved: false, reason: "review_rejected" };
    return { approved: true, titlePt: product.data.public_title_pt,
      summaryPt: product.data.public_summary_pt };
  }
}
