import { createHash } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";

interface BacktestOptions { from: string; to: string; area?: "pix" | "cards"; }
interface GroupRow {
  area: "pix" | "cards"; rule_id: string; rule_hash: string; rule_json: string;
  first_evaluated_at: string; last_evaluated_at: string;
  rule_variants: number; evaluated: number; honest: number; active_blocks: number;
  shadow_blocks: number; incremental_blocks: number; active_step_ups: number;
  shadow_step_ups: number; matched: number;
}

function timestamp(value: string): string {
  if (!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(value) ||
    !Number.isFinite(Date.parse(value)) || new Date(value).toISOString() !== value)
    throw new Error("RISK_BACKTEST_WINDOW_INVALID");
  return value;
}

export function backtestShadowRules(db: DatabaseSync, options: BacktestOptions) {
  const from = timestamp(options.from);
  const to = timestamp(options.to);
  if (from >= to || (options.area !== undefined && options.area !== "pix" && options.area !== "cards"))
    throw new Error("RISK_BACKTEST_WINDOW_INVALID");
  const labels = db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='sim_risk_labels'").get();
  if (!labels) throw new Error("RISK_BACKTEST_LABELS_UNAVAILABLE");
  const rows = db.prepare(`SELECT d.area,s.rule_id,s.rule_hash,MIN(s.rule_json) rule_json,
      MIN(s.created_at) first_evaluated_at,MAX(s.created_at) last_evaluated_at,
      COUNT(DISTINCT s.rule_json) rule_variants,COUNT(*) evaluated,
      COUNT(l.decision_id) honest,
      SUM(CASE WHEN l.decision_id IS NOT NULL AND s.active_outcome IN ('hold','decline') THEN 1 ELSE 0 END) active_blocks,
      SUM(CASE WHEN l.decision_id IS NOT NULL AND s.shadow_outcome IN ('hold','decline') THEN 1 ELSE 0 END) shadow_blocks,
      SUM(CASE WHEN l.decision_id IS NOT NULL AND s.active_outcome NOT IN ('hold','decline')
        AND s.shadow_outcome IN ('hold','decline') THEN 1 ELSE 0 END) incremental_blocks,
      SUM(CASE WHEN l.decision_id IS NOT NULL AND s.active_outcome='step_up' THEN 1 ELSE 0 END) active_step_ups,
      SUM(CASE WHEN l.decision_id IS NOT NULL AND s.shadow_outcome='step_up' THEN 1 ELSE 0 END) shadow_step_ups,
      SUM(CASE WHEN l.decision_id IS NOT NULL AND s.matched=1 THEN 1 ELSE 0 END) matched
    FROM risk_shadow_evaluations s JOIN risk_decisions d ON d.id=s.decision_id
    LEFT JOIN sim_risk_labels l ON l.decision_id=d.id AND l.request_id=d.trace_id
      AND l.label='honest' AND l.source='customer_simulator_v1'
    WHERE s.created_at>=? AND s.created_at<? AND (? IS NULL OR d.area=?)
    GROUP BY d.area,s.rule_id,s.rule_hash
    ORDER BY d.area,s.rule_id,s.rule_hash`).all(from, to, options.area ?? null, options.area ?? null) as
    unknown as GroupRow[];
  const rules = rows.map((row) => {
    let rule: unknown;
    try { rule = JSON.parse(row.rule_json); } catch { throw new Error("RISK_BACKTEST_RULE_INVALID"); }
    if (row.rule_variants !== 1 || createHash("sha256").update(row.rule_json).digest("hex") !== row.rule_hash ||
      !rule || typeof rule !== "object" || Array.isArray(rule) ||
      (rule as { id?: unknown }).id !== row.rule_id ||
      (rule as { mode?: unknown }).mode !== "shadow") throw new Error("RISK_BACKTEST_RULE_INVALID");
    const denominator = row.honest;
    return { area: row.area, rule_id: row.rule_id, rule_hash: row.rule_hash,
      first_evaluated_at: row.first_evaluated_at,
      last_evaluated_at: row.last_evaluated_at,
      evaluated_decisions: row.evaluated, labeled_honest_decisions: denominator,
      unlabeled_decisions: row.evaluated - denominator, matched_honest_decisions: row.matched,
      active_blocks: row.active_blocks, shadow_blocks: row.shadow_blocks,
      incremental_false_blocks: row.incremental_blocks,
      active_step_ups: row.active_step_ups, shadow_step_ups: row.shadow_step_ups,
      active_block_rate: denominator ? row.active_blocks / denominator : null,
      shadow_false_block_rate: denominator ? row.shadow_blocks / denominator : null,
      incremental_false_block_rate: denominator ? row.incremental_blocks / denominator : null };
  });
  return { schema_version: 1, label_source: "customer_simulator_v1",
    window: { from, to, basis: "simulated_decision_time", end_exclusive: true },
    area: options.area ?? null, rules };
}
