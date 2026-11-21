import type { DictFraudCounter } from "../ecosystem/dict-fraud-history.ts";
import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import type { DatabaseSync } from "node:sqlite";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { newId } from "../id.ts";
import { currentTrace, withTrace, type TelemetryStore } from "../telemetry.ts";
import { backtestShadowRules } from "./shadow-backtest.ts";
import { loadRiskRolloutPolicy } from "./rollout-policy.ts";

export type RiskOutcome = "approve" | "step_up" | "hold" | "decline";
export interface RiskDecision {
  id: string; area: "pix" | "cards"; customer_id: string; account_id: string;
  entity_id: string; amount_cents: number; score: number; outcome: RiskOutcome;
  reason_codes: string[]; features: Record<string, number>; trace_id: string;
  created_at: string;
}
export interface CustomerRiskProfile {
  customer_id: string; risk_tier: "low" | "medium" | "high";
  verified_income_cents: number; declared_income_cents: number | null;
  tenure_days: number;
}
export interface PixRecipientEvidence {
  exists: boolean;
  flagged: boolean;
  fraudHistory: DictFraudCounter;
}
interface RiskCondition { feature: string; operator: "gte" | "lt"; value: number; }
export interface RiskRule extends RiskCondition { id: string; points: number; reason: string;
  all?: RiskCondition[]; any?: RiskCondition[]; mode?: "active" | "shadow"; }
interface RuleSet { version: number; thresholds: { step_up: number; hold: number; decline: number };
  rules: RiskRule[]; }
type RiskArea = "pix" | "cards";
type RolloutAction = "promote" | "emergency_activate" | "disable";
// Legacy active defaults are pinned so a JSON-only change cannot bypass rollout.
const BASELINE_RULESET_HASHES: Record<RiskArea, string> = {
  pix: "e0af06c87c7409f94cde129d3ad1b9d5f58f34c6d77a854af9c607f7e9cea161",
  cards: "39478e7065b3fb8e6dced8edc881216b2b697608407cdecfb373efd8d34f43a7",
};
function ruleHash(rule: RiskRule): string {
  return createHash("sha256").update(JSON.stringify(rule)).digest("hex");
}
const FEATURES: Record<"pix" | "cards", ReadonlySet<string>> = {
  pix: new Set(["destination_flagged", "destination_fraud_history_known",
    "destination_fraud_history_complete_90d", "destination_fraud_history_complete_12m",
    "destination_fraud_marks_90d", "destination_fraud_marks_12m", "device_age_minutes", "new_beneficiary",
    "new_beneficiaries_24h", "amount_vs_average_pct", "velocity_1m", "velocity_10m", "velocity_1h",
    "fan_in_10m", "atypical_hour", "customer_risk_tier", "customer_tenure_days",
    "income_mismatch_pct", "recent_phone_replacement", "recent_password_change"]),
  cards: new Set(["cvv_failed", "small_amount", "failed_cvv_10m", "merchant_spread_10m",
    "customer_risk_tier", "customer_tenure_days", "income_mismatch_pct",
    "bin_merchant_failed_cards_10m"]),
};

function validCondition(condition: unknown, area: "pix" | "cards"): condition is RiskCondition {
  if (!condition || typeof condition !== "object" || Array.isArray(condition)) return false;
  const value = condition as Partial<RiskCondition>;
  return typeof value.feature === "string" && FEATURES[area].has(value.feature) &&
    (value.operator === "gte" || value.operator === "lt") &&
    typeof value.value === "number" && Number.isFinite(value.value) && value.value >= 0;
}

function validConditions(conditions: unknown, area: "pix" | "cards"): boolean {
  return conditions === undefined || (Array.isArray(conditions) && conditions.length > 0 &&
    conditions.length <= 10 && conditions.every((condition) => validCondition(condition, area) &&
      Object.keys(condition).every((key) => ["feature", "operator", "value"].includes(key))));
}

export function loadRules(area: "pix" | "cards", directory =
  fileURLToPath(new URL(`../../../../rules/${area}/`, import.meta.url))): RuleSet {
  const value: unknown = JSON.parse(readFileSync(join(directory, "default.json"), "utf8"));
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("RISK_RULES_INVALID");
  const rules = value as Partial<RuleSet>;
  const limits = rules.thresholds;
  if (rules.version !== 1 || !limits || !Array.isArray(rules.rules) ||
    !Number.isSafeInteger(limits.step_up) || !Number.isSafeInteger(limits.hold) ||
    !Number.isSafeInteger(limits.decline) || limits.step_up! < 1 ||
    limits.step_up! >= limits.hold! || limits.hold! >= limits.decline! ||
    limits.decline! > 1000) throw new Error("RISK_RULES_INVALID");
  if (createHash("sha256").update(JSON.stringify(value)).digest("hex") !==
    BASELINE_RULESET_HASHES[area]) throw new Error("RISK_RULES_BASELINE_CHANGED");
  const names = readdirSync(directory);
  if (names.some((name) => name.endsWith(".yaml"))) throw new Error("RISK_RULES_INVALID");
  const extras = names.filter((name) => name !== "default.json" &&
    name !== "limits.json" && name.endsWith(".json")).sort();
  for (const name of extras) {
    if (!/^[a-z0-9][a-z0-9_-]*\.json$/.test(name)) throw new Error("RISK_RULES_INVALID");
    const extra: unknown = JSON.parse(readFileSync(join(directory, name), "utf8"));
    if (!extra || typeof extra !== "object" || Array.isArray(extra) ||
      Object.keys(extra).some((key) => !["version", "rules"].includes(key)) ||
      (extra as { version?: unknown }).version !== 1 ||
      !Array.isArray((extra as { rules?: unknown }).rules)) throw new Error("RISK_RULES_INVALID");
    const supplemental = (extra as { rules: RiskRule[] }).rules;
    if (supplemental.some((rule) => !rule || rule.mode !== "shadow"))
      throw new Error("RISK_RULES_ROLLOUT_REQUIRED");
    rules.rules.push(...supplemental);
  }
  if (rules.rules.length > 20) throw new Error("RISK_RULES_INVALID");
  const ids = new Set<string>();
  for (const rule of rules.rules) {
    if (!rule || typeof rule.id !== "string" || !/^[A-Z0-9_-]{1,64}$/.test(rule.id) ||
      ids.has(rule.id) || !validCondition(rule, area) ||
      !validConditions(rule.all, area) || !validConditions(rule.any, area) ||
      (rule.mode !== undefined && rule.mode !== "active" && rule.mode !== "shadow") ||
      !Number.isSafeInteger(rule.points) ||
      rule.points < 0 || rule.points > 1000 ||
      typeof rule.reason !== "string" || !/^[A-Z0-9_-]{1,64}$/.test(rule.reason))
      throw new Error("RISK_RULES_INVALID");
    ids.add(rule.id);
  }
  return rules as RuleSet;
}

export function evaluateRiskRules(config: RuleSet, features: Record<string, number>): {
  score: number; outcome: RiskOutcome; reasonCodes: string[]; matchedRuleIds: string[];
} {
  let score = 0;
  const reasonCodes: string[] = [];
  const matchedRuleIds: string[] = [];
  for (const rule of config.rules) {
    if (rule.mode === "shadow") continue;
    const matches = (condition: RiskCondition): boolean => {
      const value = features[condition.feature];
      if (value === undefined || !Number.isFinite(value)) throw new Error("RISK_FEATURE_INVALID");
      return condition.operator === "gte" ? value >= condition.value : value < condition.value;
    };
    // Evaluate every referenced feature even if an earlier condition fails.
    const root = matches(rule);
    const all = rule.all?.map(matches) ?? [];
    const any = rule.any?.map(matches) ?? [];
    if (root && all.every(Boolean) && (any.length === 0 || any.some(Boolean))) {
      score = Math.min(1000, score + rule.points);
      reasonCodes.push(rule.reason);
      matchedRuleIds.push(rule.id);
    }
  }
  const outcome: RiskOutcome = score >= config.thresholds.decline ? "decline" :
    score >= config.thresholds.hold ? "hold" :
      score >= config.thresholds.step_up ? "step_up" : "approve";
  return { score, outcome, reasonCodes, matchedRuleIds };
}

export class RiskEngine {
  private readonly db: DatabaseSync;
  private readonly now: () => Date;
  private readonly telemetry: TelemetryStore;
  private readonly recipientEvidence: (accountId: string, now: Date) => PixRecipientEvidence;
  private pixRules = loadRules("pix");
  private cardRules = loadRules("cards");
  private readonly rolloutPolicy = loadRiskRolloutPolicy();
  private localFalseHoldProbeKey: string | null = null;

  setLocalFalseHoldProbeKey(key: string | null): void {
    if (key !== null && !/^sim:[0-9a-f-]{36}:0$/.test(key))
      throw new Error("RISK_LOCAL_PROBE_KEY_INVALID");
    this.localFalseHoldProbeKey = key;
  }
  constructor(db: DatabaseSync, now: () => Date, telemetry: TelemetryStore,
    recipientEvidence: (accountId: string, now: Date) => PixRecipientEvidence) {
    this.db = db; this.now = now; this.telemetry = telemetry;
    this.recipientEvidence = recipientEvidence;
    db.exec(`CREATE TABLE IF NOT EXISTS risk_decisions (
      id TEXT PRIMARY KEY, area TEXT NOT NULL, customer_id TEXT NOT NULL REFERENCES customers(id),
      account_id TEXT NOT NULL REFERENCES accounts(id), entity_id TEXT NOT NULL,
      amount_cents INTEGER NOT NULL, score INTEGER NOT NULL, outcome TEXT NOT NULL,
      reason_codes_json TEXT NOT NULL, features_json TEXT NOT NULL,
      trace_id TEXT NOT NULL, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS risk_shadow_evaluations (
      decision_id TEXT NOT NULL REFERENCES risk_decisions(id), rule_id TEXT NOT NULL,
      rule_hash TEXT NOT NULL, rule_json TEXT NOT NULL, active_score INTEGER NOT NULL,
      active_outcome TEXT NOT NULL, shadow_score INTEGER NOT NULL, shadow_outcome TEXT NOT NULL,
      matched INTEGER NOT NULL CHECK(matched IN (0,1)), created_at TEXT NOT NULL,
      PRIMARY KEY(decision_id,rule_id)
    );
    CREATE INDEX IF NOT EXISTS risk_shadow_window
      ON risk_shadow_evaluations(created_at,rule_id,rule_hash);
    CREATE TABLE IF NOT EXISTS risk_rule_rollout_events (
      id INTEGER PRIMARY KEY, area TEXT NOT NULL CHECK(area IN ('pix','cards')),
      rule_id TEXT NOT NULL, rule_hash TEXT NOT NULL,
      action TEXT NOT NULL CHECK(action IN ('promote','emergency_activate','disable')),
      actor TEXT NOT NULL, policy_hash TEXT NOT NULL, evidence_json TEXT NOT NULL,
      created_at TEXT NOT NULL, real_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS risk_rule_rollout_latest
      ON risk_rule_rollout_events(area,rule_id,id DESC);
    CREATE TRIGGER IF NOT EXISTS risk_rule_rollout_events_no_update
      BEFORE UPDATE ON risk_rule_rollout_events
      BEGIN SELECT RAISE(ABORT,'RISK_ROLLOUT_EVENT_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS risk_rule_rollout_events_no_delete
      BEFORE DELETE ON risk_rule_rollout_events
      BEGIN SELECT RAISE(ABORT,'RISK_ROLLOUT_EVENT_IMMUTABLE'); END;
    CREATE INDEX IF NOT EXISTS risk_customer_time ON risk_decisions(customer_id,created_at);
    CREATE INDEX IF NOT EXISTS risk_area_time ON risk_decisions(area,created_at);
    CREATE INDEX IF NOT EXISTS risk_trace ON risk_decisions(trace_id);
    CREATE INDEX IF NOT EXISTS risk_pix_initiated ON pix_transfers(from_account,initiated_at);
    CREATE INDEX IF NOT EXISTS risk_pix_beneficiary ON pix_transfers(from_account,to_account,status);
    CREATE INDEX IF NOT EXISTS risk_pix_settled ON pix_transfers(from_account,settled_at,to_account);
    CREATE TABLE IF NOT EXISTS customer_risk_profiles (
      customer_id TEXT PRIMARY KEY REFERENCES customers(id),
      risk_tier TEXT NOT NULL CHECK(risk_tier IN ('low','medium','high')),
      verified_income_cents INTEGER NOT NULL CHECK(verified_income_cents>=0),
      declared_income_cents INTEGER CHECK(declared_income_cents>=0),
      updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS customer_risk_profile_changes (
      id TEXT PRIMARY KEY, customer_id TEXT NOT NULL REFERENCES customers(id),
      actor TEXT NOT NULL, risk_tier TEXT NOT NULL,
      verified_income_cents INTEGER NOT NULL, declared_income_cents INTEGER,
      changed_at TEXT NOT NULL
    );
    CREATE TRIGGER IF NOT EXISTS customer_risk_profile_changes_no_update
      BEFORE UPDATE ON customer_risk_profile_changes
      BEGIN SELECT RAISE(ABORT, 'RISK_PROFILE_HISTORY_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS customer_risk_profile_changes_no_delete
      BEFORE DELETE ON customer_risk_profile_changes
      BEGIN SELECT RAISE(ABORT, 'RISK_PROFILE_HISTORY_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS customer_risk_profile_seed AFTER INSERT ON customers
    BEGIN
      INSERT INTO customer_risk_profiles VALUES (
        NEW.id, CASE WHEN NEW.risk_score>=85 THEN 'high'
          WHEN NEW.risk_score>=50 THEN 'medium' ELSE 'low' END,
        CASE NEW.persona WHEN 'salaried' THEN 450000 WHEN 'merchant' THEN 650000
          WHEN 'student' THEN 120000 WHEN 'retiree' THEN 300000 WHEN 'gig' THEN 340000
          WHEN 'saver' THEN 750000 WHEN 'night_owl' THEN 380000 ELSE 200000 END,
        NULL, NEW.created_at
      );
    END;`);
    db.exec(`INSERT OR IGNORE INTO customer_risk_profiles
      (customer_id,risk_tier,verified_income_cents,declared_income_cents,updated_at)
      SELECT id,CASE WHEN risk_score>=85 THEN 'high' WHEN risk_score>=50 THEN 'medium' ELSE 'low' END,
        CASE persona WHEN 'salaried' THEN 450000 WHEN 'merchant' THEN 650000
          WHEN 'student' THEN 120000 WHEN 'retiree' THEN 300000 WHEN 'gig' THEN 340000
          WHEN 'saver' THEN 750000 WHEN 'night_owl' THEN 380000 ELSE 200000 END,
        NULL,created_at FROM customers;`);
    this.effectiveRules("pix");
    this.effectiveRules("cards");
  }

  private configuredRules(area: RiskArea): RuleSet {
    return area === "pix" ? this.pixRules : this.cardRules;
  }

  private shadowRule(area: RiskArea, ruleId: string): RiskRule {
    const rule = this.configuredRules(area).rules.find((item) => item.id === ruleId);
    if (!rule || rule.mode !== "shadow") throw new Error("RISK_ROLLOUT_RULE_NOT_SHADOW");
    return rule;
  }

  private latestRollout(area: RiskArea, ruleId: string):
    { action: RolloutAction; rule_hash: string } | undefined {
    return this.db.prepare(`SELECT action,rule_hash FROM risk_rule_rollout_events
      WHERE area=? AND rule_id=? ORDER BY id DESC LIMIT 1`).get(area, ruleId) as
      { action: RolloutAction; rule_hash: string } | undefined;
  }

  private effectiveRules(area: RiskArea): { active: RuleSet; shadows: RiskRule[] } {
    let config = this.configuredRules(area);
    const rules: RiskRule[] = [];
    const shadows: RiskRule[] = [];
    const activeEvents = this.db.prepare(`SELECT e.rule_id FROM risk_rule_rollout_events e
      WHERE e.area=? AND e.id=(SELECT MAX(id) FROM risk_rule_rollout_events
        WHERE area=e.area AND rule_id=e.rule_id)
        AND e.action IN ('promote','emergency_activate')`).all(area) as
      unknown as { rule_id: string }[];
    let present = new Set(config.rules.map((rule) => rule.id));
    if (activeEvents.some((event) => !present.has(event.rule_id))) {
      const reloaded = loadRules(area);
      const loadedIds = new Set(reloaded.rules.map((rule) => rule.id));
      if (activeEvents.every((event) => loadedIds.has(event.rule_id))) {
        config = reloaded;
        if (area === "pix") this.pixRules = reloaded;
        else this.cardRules = reloaded;
        present = loadedIds;
      }
    }
    if (activeEvents.some((event) => !present.has(event.rule_id)))
      throw new Error("RISK_ROLLOUT_RULE_MISSING");
    for (const rule of config.rules) {
      if (rule.mode !== "shadow") { rules.push(rule); continue; }
      const state = this.latestRollout(area, rule.id);
      if (state?.action === "promote" || state?.action === "emergency_activate") {
        if (state.rule_hash !== ruleHash(rule)) throw new Error("RISK_ROLLOUT_RULE_CHANGED");
        rules.push({ ...rule, mode: "active" });
      } else shadows.push(rule);
    }
    return { active: { ...config, rules }, shadows };
  }

  private appendRollout(area: RiskArea, rule: RiskRule, action: RolloutAction,
    actor: string, evidence: Record<string, unknown>): void {
    if (!/^[A-Za-z0-9_-]{1,80}$/.test(actor)) throw new Error("RISK_ROLLOUT_ACTOR_INVALID");
    this.db.prepare(`INSERT INTO risk_rule_rollout_events
      (area,rule_id,rule_hash,action,actor,policy_hash,evidence_json,created_at,real_at)
      VALUES (?,?,?,?,?,?,?,?,?)`).run(area, rule.id, ruleHash(rule), action, actor,
        this.rolloutPolicy.hash, JSON.stringify({ policy_version: this.rolloutPolicy.policy.version,
          policy_bytes: this.rolloutPolicy.bytes, ...evidence }), this.now().toISOString(),
        new Date().toISOString());
  }

  promoteShadowRule(area: RiskArea, ruleId: string, from: string, to: string,
    actor: string): void {
    if (area !== "pix" && area !== "cards") throw new Error("RISK_ROLLOUT_AREA_INVALID");
    if (this.db.isTransaction) throw new Error("RISK_ROLLOUT_TRANSACTION_ACTIVE");
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const rule = this.shadowRule(area, ruleId);
      if (["promote", "emergency_activate"].includes(this.latestRollout(area, ruleId)?.action ?? ""))
        throw new Error("RISK_ROLLOUT_ALREADY_ACTIVE");
      const report = backtestShadowRules(this.db, { from, to, area });
      const policy = this.rolloutPolicy.policy;
      const windowMs = Date.parse(to) - Date.parse(from);
      if (windowMs < policy.min_shadow_minutes * 60_000 ||
        Date.parse(to) > this.now().getTime()) throw new Error("RISK_ROLLOUT_WINDOW_SHORT");
      const variants = report.rules.filter((item) => item.rule_id === ruleId);
      if (variants.length !== 1 || variants[0]!.rule_hash !== ruleHash(rule))
        throw new Error("RISK_ROLLOUT_RULE_CHANGED");
      const sample = variants[0]!;
      if (Date.parse(to) - Date.parse(sample.first_evaluated_at) <
          policy.min_shadow_minutes * 60_000 ||
        Date.parse(to) - Date.parse(sample.last_evaluated_at) > 60 * 60_000 ||
        sample.labeled_honest_decisions < policy.min_labeled_honest_decisions ||
        sample.unlabeled_decisions / sample.evaluated_decisions > policy.max_unlabeled_fraction ||
        sample.incremental_false_block_rate === null ||
        sample.incremental_false_block_rate > policy.max_incremental_false_block_rate)
        throw new Error("RISK_ROLLOUT_PROOF_INSUFFICIENT");
      const trailingStartMs = Date.parse(to) - policy.min_shadow_minutes * 60_000;
      const requiredHours = Math.ceil(policy.min_shadow_minutes / 60);
      const coveredHours = new Set<number>();
      for (const row of this.db.prepare(`SELECT s.created_at FROM risk_shadow_evaluations s
        JOIN risk_decisions d ON d.id=s.decision_id
        JOIN sim_risk_labels l ON l.decision_id=d.id AND l.request_id=d.trace_id
          AND l.label='honest' AND l.source='customer_simulator_v1'
        WHERE d.area=? AND s.rule_id=? AND s.rule_hash=?
          AND s.created_at>=? AND s.created_at<?`).iterate(area, ruleId, ruleHash(rule),
          new Date(trailingStartMs).toISOString(), to) as Iterable<{ created_at: string }>) {
        const evaluatedMs = Date.parse(row.created_at);
        if (!Number.isFinite(evaluatedMs)) throw new Error("RISK_ROLLOUT_PROOF_INSUFFICIENT");
        const hour = Math.floor((evaluatedMs - trailingStartMs) / 3_600_000);
        if (hour < 0 || hour >= requiredHours)
          throw new Error("RISK_ROLLOUT_PROOF_INSUFFICIENT");
        coveredHours.add(hour);
      }
      if (coveredHours.size !== requiredHours)
        throw new Error("RISK_ROLLOUT_PROOF_INSUFFICIENT");
      this.appendRollout(area, rule, "promote", actor, {
        from, to,
        evaluated_decisions: sample.evaluated_decisions,
        labeled_honest_decisions: sample.labeled_honest_decisions,
        covered_hour_buckets: coveredHours.size,
        incremental_false_blocks: sample.incremental_false_blocks,
        incremental_false_block_rate: sample.incremental_false_block_rate });
      this.db.exec("COMMIT");
    } catch (error) { this.db.exec("ROLLBACK"); throw error; }
  }

  disableShadowRule(area: RiskArea, ruleId: string, actor: string): void {
    if (area !== "pix" && area !== "cards") throw new Error("RISK_ROLLOUT_AREA_INVALID");
    if (this.db.isTransaction) throw new Error("RISK_ROLLOUT_TRANSACTION_ACTIVE");
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const rule = this.shadowRule(area, ruleId);
      const state = this.latestRollout(area, ruleId);
      if (!state || !["promote", "emergency_activate"].includes(state.action) ||
        state.rule_hash !== ruleHash(rule)) throw new Error("RISK_ROLLOUT_NOT_ACTIVE");
      this.appendRollout(area, rule, "disable", actor, { prior_action: state.action });
      this.db.exec("COMMIT");
    } catch (error) { this.db.exec("ROLLBACK"); throw error; }
  }

  activateEmergencyRule(area: RiskArea, ruleId: string, actor: string,
    evidence: { incident_id: string; task_id: string; run_id: string;
      head_sha: string; reviewer_id: string }): void {
    if (area !== "pix" && area !== "cards" ||
      !/^incident_[A-Za-z0-9_-]{1,100}$/.test(evidence.incident_id) ||
      !/^task_[A-Za-z0-9_-]{1,100}$/.test(evidence.task_id) ||
      !/^[A-Za-z0-9_-]{1,100}$/.test(evidence.run_id) ||
      !/^[0-9a-f]{40}$/.test(evidence.head_sha) ||
      !/^[A-Za-z0-9_-]{1,100}$/.test(evidence.reviewer_id))
      throw new Error("RISK_ROLLOUT_EMERGENCY_EVIDENCE_INVALID");
    if (this.db.isTransaction) throw new Error("RISK_ROLLOUT_TRANSACTION_ACTIVE");
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const incident = this.db.prepare(`SELECT i.severity FROM sentinel_incidents i
        JOIN blue_tasks t ON t.incident_id=i.id
        WHERE i.id=? AND i.area=? AND t.id=? AND t.state='merged'
          AND t.kind='patch_rule'`).get(evidence.incident_id, area, evidence.task_id) as
        { severity: string } | undefined;
      if (incident?.severity !== "critical") throw new Error("RISK_ROLLOUT_NOT_CRITICAL");
      const rule = this.shadowRule(area, ruleId);
      if (["promote", "emergency_activate"].includes(this.latestRollout(area, ruleId)?.action ?? ""))
        throw new Error("RISK_ROLLOUT_ALREADY_ACTIVE");
      this.appendRollout(area, rule, "emergency_activate", actor, evidence);
      this.db.exec("COMMIT");
    } catch (error) { this.db.exec("ROLLBACK"); throw error; }
  }

  // Confirms this producer can write to its telemetry path; it is not a risk decision.
  heartbeat(): void {
    this.telemetry.emit({ source: "risk", category: "health", action: "heartbeat",
      outcome: "success", message: "Risk telemetry heartbeat" });
  }

  profile(customerId: string): CustomerRiskProfile {
    const row = this.db.prepare(`SELECT p.customer_id,p.risk_tier,p.verified_income_cents,
      p.declared_income_cents,c.created_at FROM customer_risk_profiles p
      JOIN customers c ON c.id=p.customer_id WHERE p.customer_id=?`).get(customerId) as
      (Omit<CustomerRiskProfile, "tenure_days"> & { created_at: string }) | undefined;
    if (!row) throw new Error("RISK_PROFILE_NOT_FOUND");
    const { created_at, ...profile } = row;
    return { ...profile, tenure_days: Math.max(0,
      Math.floor((this.now().getTime() - Date.parse(created_at)) / 86_400_000)) };
  }

  setVerifiedProfile(customerId: string, riskTier: CustomerRiskProfile["risk_tier"],
    verifiedIncomeCents: number, actor: string): CustomerRiskProfile {
    if (!["low", "medium", "high"].includes(riskTier) ||
      !Number.isSafeInteger(verifiedIncomeCents) || verifiedIncomeCents < 0 ||
      !/^[a-zA-Z0-9_-]{1,80}$/.test(actor)) throw new Error("RISK_PROFILE_INVALID");
    const ownTransaction = !this.db.isTransaction;
    if (ownTransaction) this.db.exec("BEGIN IMMEDIATE");
    try {
      const now = this.now().toISOString();
      const result = this.db.prepare(`UPDATE customer_risk_profiles
        SET risk_tier=?,verified_income_cents=?,updated_at=? WHERE customer_id=?`)
        .run(riskTier, verifiedIncomeCents, now, customerId);
      if (result.changes !== 1) throw new Error("RISK_PROFILE_NOT_FOUND");
      this.recordProfileChange(customerId, actor, now);
      const profile = this.profile(customerId);
      if (ownTransaction) this.db.exec("COMMIT");
      return profile;
    } catch (error) {
      if (ownTransaction) this.db.exec("ROLLBACK");
      throw error;
    }
  }

  recordDeclaredIncome(customerId: string, declaredIncomeCents: number): void {
    if (!Number.isSafeInteger(declaredIncomeCents) || declaredIncomeCents < 0)
      throw new Error("RISK_PROFILE_INVALID");
    const now = this.now().toISOString();
    const result = this.db.prepare(`UPDATE customer_risk_profiles
      SET declared_income_cents=?,updated_at=? WHERE customer_id=?`)
      .run(declaredIncomeCents, now, customerId);
    if (result.changes !== 1) throw new Error("RISK_PROFILE_NOT_FOUND");
    this.recordProfileChange(customerId, customerId, now);
  }

  private recordProfileChange(customerId: string, actor: string, now: string): void {
    const profile = this.profile(customerId);
    this.db.prepare(`INSERT INTO customer_risk_profile_changes VALUES (?,?,?,?,?,?,?)`)
      .run(newId("risk_profile_change", this.now().getTime()), customerId, actor,
        profile.risk_tier, profile.verified_income_cents, profile.declared_income_cents, now);
  }

  private profileFeatures(customerId: string): Record<string, number> {
    const profile = this.profile(customerId);
    return {
      customer_risk_tier: profile.risk_tier === "high" ? 2 : profile.risk_tier === "medium" ? 1 : 0,
      customer_tenure_days: profile.tenure_days,
      income_mismatch_pct: profile.declared_income_cents === null ? 100 :
        profile.verified_income_cents === 0 ? (profile.declared_income_cents > 0 ? 100_000 : 100) :
          Math.min(100_000, Math.round(profile.declared_income_cents / profile.verified_income_cents * 100)),
    };
  }

  private decide(area: "pix" | "cards", input: { customerId: string; accountId: string;
    entityId: string; amountCents: number; labProbeKey?: string },
    features: Record<string, number>): RiskDecision {
    const { active: config, shadows } = this.effectiveRules(area);
    const baseline = evaluateRiskRules(config, features);
    // A local, one-request scoring fault; the real features and rules remain intact
    // so an independent reviewer can reconstruct the legitimate decision.
    const falseHold = area === "pix" && input.labProbeKey !== undefined &&
      input.labProbeKey === this.localFalseHoldProbeKey &&
      baseline.outcome === "approve";
    const { score, outcome, reasonCodes: reasons, matchedRuleIds } = falseHold ?
      { ...baseline, score: config.thresholds.hold, outcome: "hold" as const } : baseline;
    const traceId = this.telemetry.emit({ source: "risk", category: area,
      action: "decision", outcome: outcome === "approve" ? "success" : "failure",
      severity: outcome === "approve" ? "info" : "warn", userId: input.customerId,
      accountId: input.accountId, amountCents: input.amountCents,
      counterparty: input.entityId, riskScore: score, reasonCodes: reasons,
      message: `Risk decision ${outcome}` });
    if (outcome !== "approve") withTrace(currentTrace() ?? traceId, () => {
      for (let index = 0; index < matchedRuleIds.length; index++)
        this.telemetry.emit({ source: "risk", category: area, action: "rule_match",
          outcome: "failure", severity: "warn", userId: input.customerId,
          accountId: input.accountId, counterparty: input.entityId,
          amountCents: input.amountCents, riskScore: score,
          ruleId: matchedRuleIds[index]!, reasonCodes: [reasons[index]!],
          message: `Risk rule matched for ${outcome}` });
    });
    const decision: RiskDecision = { id: newId("risk", this.now().getTime()), area,
      customer_id: input.customerId, account_id: input.accountId, entity_id: input.entityId,
      amount_cents: input.amountCents, score, outcome, reason_codes: reasons,
      features, trace_id: traceId, created_at: this.now().toISOString() };
    this.db.prepare(`INSERT INTO risk_decisions VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`)
      .run(decision.id, area, input.customerId, input.accountId, input.entityId,
        input.amountCents, score, outcome, JSON.stringify(reasons), JSON.stringify(features),
        currentTrace() ?? traceId, decision.created_at);
    for (const rule of shadows) {
      const shadow = evaluateRiskRules({ ...config, rules: [
        ...config.rules, { ...rule, mode: "active" },
      ] }, features);
      const ruleJson = JSON.stringify(rule);
      const ruleHash = createHash("sha256").update(ruleJson).digest("hex");
      this.db.prepare(`INSERT INTO risk_shadow_evaluations
        (decision_id,rule_id,rule_hash,rule_json,active_score,active_outcome,shadow_score,
         shadow_outcome,matched,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)`)
        .run(decision.id, rule.id, ruleHash, ruleJson, score, outcome, shadow.score,
          shadow.outcome, Number(shadow.matchedRuleIds.includes(rule.id)), decision.created_at);
    }
    return decision;
  }

  evaluatePix(input: { customerId: string; accountId: string; toAccount: string;
    amountCents: number; deviceId?: string; labProbeKey?: string;
    recipientEvidence?: PixRecipientEvidence }): RiskDecision {
    const now = this.now().getTime();
    const since = (minutes: number) => new Date(now - minutes * 60_000).toISOString();
    const recent = this.db.prepare(`SELECT COUNT(*) n,COALESCE(AVG(amount),0) average
      FROM pix_transfers WHERE from_account=? AND status='settled' AND settled_at>=?`)
      .get(input.accountId, since(43_200)) as { n: number; average: number };
    const velocity = (minutes: number) => (this.db.prepare(`SELECT COUNT(*) n FROM pix_transfers
      WHERE from_account=? AND initiated_at>=?`).get(input.accountId, since(minutes)) as { n: number }).n;
    const known = this.db.prepare(`SELECT 1 FROM pix_transfers p
      JOIN accounts a ON a.id=p.from_account
      WHERE a.customer_id=? AND p.to_account=?
        AND p.status IN ('settled','returned_partial','returned_full') LIMIT 1`)
      .get(input.customerId, input.toAccount);
    const newBeneficiaries = this.db.prepare(`SELECT COUNT(DISTINCT p.to_account) n
      FROM accounts a JOIN pix_transfers p ON p.from_account=a.id
      LEFT JOIN accounts destination ON destination.id=p.to_account
      WHERE a.customer_id=? AND p.status IN ('settled','returned_partial','returned_full')
        AND p.settled_at>=? AND p.settled_at<=?
        AND (destination.customer_id IS NULL OR destination.customer_id<>a.customer_id)
        AND NOT EXISTS (SELECT 1 FROM accounts earlier_account
          JOIN pix_transfers earlier ON earlier.from_account=earlier_account.id
          WHERE earlier_account.customer_id=a.customer_id
            AND earlier.to_account=p.to_account
            AND earlier.status IN ('settled','returned_partial','returned_full')
            AND earlier.settled_at<?)`)
      .get(input.customerId, since(1_440), this.now().toISOString(), since(1_440)) as { n: number };
    const recipient = input.recipientEvidence ??
      this.recipientEvidence(input.toAccount, this.now());
    const device = input.deviceId && this.db.prepare("SELECT 1 FROM sqlite_master WHERE name='auth_devices'").get()
      ? this.db.prepare("SELECT first_seen_at,bound_at FROM auth_devices WHERE id=?")
        .get(input.deviceId) as { first_seen_at: string; bound_at: string | null } | undefined : undefined;
    const firstSeenAt = device ? Date.parse(device.first_seen_at) : NaN;
    const boundAt = device?.bound_at ? Date.parse(device.bound_at) : NaN;
    const deviceAgeMinutes = !device ? 1_000_000 :
      !Number.isFinite(firstSeenAt) || !Number.isFinite(boundAt) ? 0 :
        Math.max(0, Math.floor((now - Math.max(firstSeenAt, boundAt)) / 60_000));
    const recentPhoneReplacement = (this.db.prepare("PRAGMA table_info(customer_contact_changes)")
      .all() as { name: string }[]).some((column) => column.name === "phone_replaced")
      ? this.db.prepare(`SELECT 1 FROM customer_contact_changes WHERE customer_id=?
        AND phone_replaced=1 AND changed_at>=? AND changed_at<=? LIMIT 1`)
        .get(input.customerId, since(60), this.now().toISOString()) : undefined;
    const recentPasswordChange = this.db.prepare(`SELECT 1 FROM sqlite_master
      WHERE type='table' AND name='auth_password_changes'`).get()
      ? this.db.prepare(`SELECT 1 FROM auth_password_changes WHERE customer_id=?
        AND replaced=1 AND changed_at>=? AND changed_at<=? LIMIT 1`)
        .get(input.customerId, since(60), this.now().toISOString()) : undefined;
    const hour = Number(new Intl.DateTimeFormat("en-GB", { timeZone: "America/Sao_Paulo",
      hour: "2-digit", hourCycle: "h23" }).format(this.now()));
    const fraudHistory = recipient.fraudHistory;
    const features = {
      destination_fraud_history_known: Number(fraudHistory.known),
      destination_fraud_history_complete_90d: Number(fraudHistory.history_complete_90d),
      destination_fraud_history_complete_12m: Number(fraudHistory.history_complete_12m),
      destination_fraud_marks_90d: fraudHistory.marks_90d ?? 0,
      destination_fraud_marks_12m: fraudHistory.marks_12m ?? 0,
      destination_flagged: recipient.flagged ? 1 : 0,
      device_age_minutes: deviceAgeMinutes,
      new_beneficiary: known ? 0 : 1,
      new_beneficiaries_24h: newBeneficiaries.n,
      amount_vs_average_pct: recent.n > 0 && recent.average > 0
        ? Math.min(100_000, Math.round(input.amountCents * 100 / recent.average)) : 100,
      velocity_1m: velocity(1), velocity_10m: velocity(10), velocity_1h: velocity(60),
      fan_in_10m: (this.db.prepare(`SELECT COUNT(DISTINCT from_account) n FROM pix_transfers
        WHERE to_account=? AND status='settled' AND settled_at>=?`)
        .get(input.toAccount, since(10)) as { n: number }).n,
      atypical_hour: hour >= 22 || hour < 6 ? 1 : 0,
      recent_phone_replacement: recentPhoneReplacement ? 1 : 0,
      recent_password_change: recentPasswordChange ? 1 : 0,
      ...this.profileFeatures(input.customerId),
    };
    return this.decide("pix", { customerId: input.customerId, accountId: input.accountId,
      entityId: input.toAccount, amountCents: input.amountCents,
      ...(input.labProbeKey ? { labProbeKey: input.labProbeKey } : {}) }, features);
  }

  evaluateCard(input: { customerId: string; accountId: string; cardId: string;
    merchantId: string; amountCents: number; cvvOk: boolean }): RiskDecision {
    const since = new Date(this.now().getTime() - 600_000).toISOString();
    const history = this.db.prepare(`SELECT COUNT(*) failed,
      COUNT(DISTINCT merchant_id) merchants FROM card_network_authorizations
      WHERE card_id=? AND cvv_ok=0 AND created_at>=?`).get(input.cardId, since) as
      { failed: number; merchants: number };
    const bin = this.db.prepare("SELECT substr(pan,1,6) bin FROM card_vault WHERE card_id=?")
      .get(input.cardId) as { bin: string } | undefined;
    const otherFailedCards = !input.cvvOk && bin ? (this.db.prepare(`SELECT COUNT(DISTINCT a.card_id) n
      FROM card_network_authorizations a JOIN card_vault v ON v.card_id=a.card_id
      WHERE a.merchant_id=? AND a.card_id<>? AND a.cvv_ok=0 AND a.created_at>=?
        AND substr(v.pan,1,6)=?`).get(input.merchantId, input.cardId, since, bin.bin) as
      { n: number }).n : 0;
    return this.decide("cards", { customerId: input.customerId, accountId: input.accountId,
      entityId: input.merchantId, amountCents: input.amountCents }, {
      cvv_failed: input.cvvOk ? 0 : 1, small_amount: input.amountCents <= 500 ? 1 : 0,
      failed_cvv_10m: history.failed, merchant_spread_10m: history.merchants,
      bin_merchant_failed_cards_10m: !input.cvvOk ? otherFailedCards + 1 : 0,
      ...this.profileFeatures(input.customerId),
    });
  }
}
