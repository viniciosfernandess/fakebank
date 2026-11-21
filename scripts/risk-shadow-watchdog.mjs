import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const thresholds = Object.fromEntries(["pix", "cards"].map((area) => [area,
  JSON.parse(readFileSync(fileURLToPath(new URL(`../rules/${area}/default.json`,
    import.meta.url)), "utf8")).thresholds]));

function matches(condition, features) {
  if (!condition || typeof condition.feature !== "string" ||
    !["gte", "lt"].includes(condition.operator) ||
    !Number.isFinite(condition.value) || condition.value < 0 ||
    !Number.isFinite(features[condition.feature])) throw new Error("SHADOW_RULE_INVALID");
  return condition.operator === "gte" ? features[condition.feature] >= condition.value :
    features[condition.feature] < condition.value;
}

function verify(row) {
  if (!row.area || !thresholds[row.area] || !row.features_json ||
    !row.rule_json || !row.rule_hash || !row.created_at ||
    row.created_at !== row.decision_created_at ||
    row.active_score !== row.score || row.active_outcome !== row.outcome ||
    !Number.isSafeInteger(row.score) || row.score < 0 || row.score > 1000 ||
    !Number.isSafeInteger(row.shadow_score) ||
    ![0, 1].includes(row.matched)) return false;
  try {
    const rule = JSON.parse(row.rule_json);
    const features = JSON.parse(row.features_json);
    if (!rule || !features || typeof features !== "object" ||
      rule.id !== row.rule_id || rule.mode !== "shadow" ||
      !Number.isSafeInteger(rule.points) || rule.points < 0 || rule.points > 1000 ||
      createHash("sha256").update(row.rule_json).digest("hex") !== row.rule_hash ||
      rule.all !== undefined && (!Array.isArray(rule.all) || !rule.all.length) ||
      rule.any !== undefined && (!Array.isArray(rule.any) || !rule.any.length)) return false;
    const root = matches(rule, features);
    const all = (rule.all ?? []).map((condition) => matches(condition, features));
    const any = (rule.any ?? []).map((condition) => matches(condition, features));
    const hit = root && all.every(Boolean) && (!any.length || any.some(Boolean));
    const score = Math.min(1000, row.score + (hit ? rule.points : 0));
    const limits = thresholds[row.area];
    const outcome = score >= limits.decline ? "decline" :
      score >= limits.hold ? "hold" : score >= limits.step_up ? "step_up" : "approve";
    return row.matched === Number(hit) && row.shadow_score === score &&
      row.shadow_outcome === outcome;
  } catch { return false; }
}

export class RiskShadowWatchdog {
  constructor(outbox, report) {
    this.outbox = outbox;
    this.report = report;
    outbox.exec(`CREATE TABLE IF NOT EXISTS risk_shadow_watch_cursor (
      id INTEGER PRIMARY KEY CHECK(id=1),last_rowid INTEGER NOT NULL CHECK(last_rowid>=0));
      INSERT OR IGNORE INTO risk_shadow_watch_cursor VALUES (1,0)`);
  }

  scan(bank) {
    if (!bank.prepare(`SELECT 1 FROM sqlite_master WHERE type='table'
      AND name='risk_shadow_evaluations'`).get()) return;
    const cursor = this.outbox.prepare(`SELECT last_rowid FROM risk_shadow_watch_cursor
      WHERE id=1`).get().last_rowid;
    const last = bank.prepare(`SELECT COALESCE(MAX(rowid),0) n
      FROM risk_shadow_evaluations`).get().n;
    if (last < cursor) {
      this.report("shadow_divergence", { kind: "ROW_ROLLBACK", last_rowid: last });
      return;
    }
    const rows = bank.prepare(`SELECT s.rowid rowid,s.*,d.area,d.score,d.outcome,
      d.features_json,d.created_at decision_created_at
      FROM risk_shadow_evaluations s
      LEFT JOIN risk_decisions d ON d.id=s.decision_id
      WHERE s.rowid>? ORDER BY s.rowid LIMIT 500`).all(cursor);
    for (const row of rows) {
      if (!verify(row)) this.report("shadow_divergence", {
        kind: "EVALUATION_MISMATCH", row_id: row.rowid });
      this.outbox.prepare(`UPDATE risk_shadow_watch_cursor SET last_rowid=? WHERE id=1`)
        .run(row.rowid);
    }
  }
}
