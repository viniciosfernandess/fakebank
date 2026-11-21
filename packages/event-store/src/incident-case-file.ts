import { createHash } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import { AREA, type Area } from "../../contracts/src/index.ts";

export interface CaseEntry {
  id: number;
  incident_id: string;
  round_id: string | null;
  kind: string;
  actor_id: string;
  attempt_no: number | null;
  source_event_seq: number | null;
  created_at: string;
  payload: Record<string, unknown>;
}
export interface CaseContext {
  payload: Record<string, unknown>;
  sha256: string;
  inherited: string[];
}

interface CaseEntryRow extends Omit<CaseEntry, "payload"> { payload_json: string; }
const clipped = (value: unknown, max: number): string => {
  const text = typeof value === "string" ? value : "";
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
};
const limited = (value: unknown, maxItems: number, maxChars: number): string[] =>
  Array.isArray(value) ? value.slice(0, maxItems).map((item) => clipped(item, maxChars)) : [];
function latest(entries: CaseEntry[], matches: (entry: CaseEntry) => boolean): CaseEntry | undefined {
  for (let index = entries.length - 1; index >= 0; index--)
    if (matches(entries[index]!)) return entries[index];
  return undefined;
}

export class IncidentCaseFile {
  private readonly db: DatabaseSync;
  constructor(db: DatabaseSync) {
    this.db = db;
    db.exec(`CREATE TABLE IF NOT EXISTS incident_case (
      id TEXT PRIMARY KEY, area TEXT NOT NULL, opened_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS incident_case_entries (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      incident_id TEXT NOT NULL REFERENCES incident_case(id),
      round_id TEXT, kind TEXT NOT NULL, actor_id TEXT NOT NULL,
      attempt_no INTEGER, source_event_seq INTEGER UNIQUE REFERENCES events(seq),
      entry_key TEXT, created_at TEXT NOT NULL, payload_json TEXT NOT NULL,
      UNIQUE(incident_id,entry_key)
    );
    CREATE INDEX IF NOT EXISTS incident_case_entries_history
      ON incident_case_entries(incident_id,created_at,id);
    CREATE TRIGGER IF NOT EXISTS incident_case_entries_no_update
      BEFORE UPDATE ON incident_case_entries
      BEGIN SELECT RAISE(ABORT, 'CASE_HISTORY_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS incident_case_entries_no_delete
      BEFORE DELETE ON incident_case_entries
      BEGIN SELECT RAISE(ABORT, 'CASE_HISTORY_IMMUTABLE'); END;`);
  }

  open(incidentId: string, area: Area, openedAt: string): void {
    this.db.prepare("INSERT OR IGNORE INTO incident_case VALUES (?,?,?)")
      .run(incidentId, area, openedAt);
    const row = this.db.prepare("SELECT area FROM incident_case WHERE id=?")
      .get(incidentId) as { area: string };
    if (row.area === "unknown")
      this.db.prepare("UPDATE incident_case SET area=? WHERE id=?").run(area, incidentId);
    else if (row.area !== area) throw new Error("CASE_AREA_MISMATCH");
  }

  ensureFromEvent(incidentId: string, area: Area | null, openedAt: string): void {
    this.db.prepare("INSERT OR IGNORE INTO incident_case VALUES (?,?,?)")
      .run(incidentId, area ?? "unknown", openedAt);
    if (area) this.db.prepare("UPDATE incident_case SET area=? WHERE id=? AND area='unknown'")
      .run(area, incidentId);
  }

  syncAllEvents(): void {
    const incidents = this.db.prepare(`SELECT e.incident_id,MIN(e.ts) opened_at,
      (SELECT area FROM events WHERE incident_id=e.incident_id AND area IS NOT NULL
        ORDER BY seq LIMIT 1) area
      FROM events e WHERE e.incident_id IS NOT NULL GROUP BY e.incident_id`)
      .all() as { incident_id: string; opened_at: string; area: string | null }[];
    for (const incident of incidents) {
      const area = AREA.safeParse(incident.area);
      this.ensureFromEvent(incident.incident_id, area.success ? area.data : null,
        incident.opened_at);
      this.syncEvents(incident.incident_id);
    }
  }

  syncEvents(incidentId: string): void {
    const rows = this.db.prepare(`SELECT e.seq,e.round_id,e.ts,e.twin_ts,e.type,e.actor_id,
      e.public_json,p.private_json FROM events e
      LEFT JOIN event_private p ON p.seq=e.seq WHERE e.incident_id=?
        AND e.seq>COALESCE((SELECT MAX(source_event_seq) FROM incident_case_entries
          WHERE incident_id=?),0) ORDER BY e.seq`)
      .all(incidentId, incidentId) as { seq: number; round_id: string | null; ts: string;
        twin_ts: string | null; type: string;
        actor_id: string; public_json: string; private_json: string | null }[];
    const insert = this.db.prepare(`INSERT OR IGNORE INTO incident_case_entries
      (incident_id,round_id,kind,actor_id,attempt_no,source_event_seq,entry_key,created_at,payload_json)
      VALUES (?,?,?,?,NULL,?,NULL,?,?)`);
    for (const row of rows) {
      const payload = { public: JSON.parse(row.public_json) as unknown,
        twin_ts: row.twin_ts,
        ...(row.private_json ? { private: JSON.parse(row.private_json) as unknown } : {}) };
      insert.run(incidentId, row.round_id, row.type, row.actor_id, row.seq,
        row.ts, JSON.stringify(payload));
    }
  }

  record(input: { incidentId: string; roundId: string | null; kind: string;
    actorId: string; attemptNo?: number; entryKey?: string; createdAt: string;
    payload: Record<string, unknown> }): number {
    const json = JSON.stringify(input.payload);
    if (Buffer.byteLength(json) > 262_144) throw new Error("CASE_ENTRY_TOO_LARGE");
    const inserted = this.db.prepare(`INSERT OR IGNORE INTO incident_case_entries
      (incident_id,round_id,kind,actor_id,attempt_no,source_event_seq,entry_key,created_at,payload_json)
      VALUES (?,?,?,?,?,NULL,?,?,?)`).run(input.incidentId, input.roundId, input.kind,
        input.actorId, input.attemptNo ?? null, input.entryKey ?? null, input.createdAt, json);
    if (inserted.changes === 1) return Number(inserted.lastInsertRowid);
    const row = this.db.prepare(`SELECT id,round_id,kind,actor_id,attempt_no,payload_json
      FROM incident_case_entries
      WHERE incident_id=? AND entry_key=?`).get(input.incidentId, input.entryKey ?? null) as
      { id: number; round_id: string | null; kind: string; actor_id: string;
        attempt_no: number | null; payload_json: string } | undefined;
    if (!row || row.round_id !== input.roundId || row.kind !== input.kind ||
      row.actor_id !== input.actorId || row.attempt_no !== (input.attemptNo ?? null) ||
      row.payload_json !== json) throw new Error("CASE_ENTRY_CONFLICT");
    return row.id;
  }

  history(incidentId: string): CaseEntry[] {
    const rows = this.db.prepare(`SELECT id,incident_id,round_id,kind,actor_id,
      attempt_no,source_event_seq,created_at,payload_json FROM incident_case_entries
      WHERE incident_id=? ORDER BY created_at,id`).all(incidentId) as unknown as CaseEntryRow[];
    return rows.map(({ payload_json, ...row }) => ({ ...row,
      payload: JSON.parse(payload_json) as Record<string, unknown> }));
  }

  private package(payload: Record<string, unknown>, inherited: string[],
    fallback: Record<string, unknown>): CaseContext {
    const sourceHash = IncidentCaseFile.digest(payload);
    const delivered = Buffer.byteLength(JSON.stringify(payload)) <= 16_384 ? payload :
      { ...fallback, source_sha256: sourceHash, context_truncated: true };
    if (Buffer.byteLength(JSON.stringify(delivered)) > 16_384)
      throw new Error("CASE_CONTEXT_FALLBACK_INVALID");
    return { payload: delivered, sha256: IncidentCaseFile.digest(delivered), inherited };
  }

  architectContext(incidentId: string, taskId: string, attemptNo: number): CaseContext {
    const entries = this.history(incidentId);
    const verified = latest(entries, (entry) => entry.kind === "task.verified" &&
      entry.payload.task_id === taskId);
    const investigation = latest(entries, (entry) => entry.kind === "dossier.investigation" &&
      (entry.payload.task as Record<string, unknown> | undefined)?.title === verified?.payload.title);
    if (!verified || !investigation) throw new Error("CASE_TASK_MISSING");
    const mapped = latest(entries, (entry) => entry.kind === "dossier.incident_map" &&
      entry.payload.task_id === taskId);
    const analysed = latest(entries, (entry) => entry.kind === "dossier.root_cause" &&
      entry.payload.task_id === taskId);
    const attempts = entries.filter((entry) =>
      (entry.payload.task_id === taskId ||
        (entry.payload.public as Record<string, unknown> | undefined)?.task_id === taskId) &&
      ["dossier.fix_design", "patch.diff", "ci.failure", "ci.result", "dossier.review",
        "dossier.rejection_report", "agent.failure", "deploy.rolled_back"].includes(entry.kind)).map((entry) => ({
      kind: entry.kind, attempt_no: entry.attempt_no,
      summary: entry.kind === "patch.diff" ? `diff ${String(entry.payload.sha256)}` :
        clipped(JSON.stringify(entry.payload), 900),
      source_sha256: IncidentCaseFile.digest(entry.payload),
    })).slice(-32);
    const sourceRootCause = (analysed?.payload ?? investigation.payload.root_cause_hypothesis) as
      Record<string, unknown> | undefined;
    const rootCause = sourceRootCause ? { class: sourceRootCause.class,
      description: clipped(sourceRootCause.explanation ?? sourceRootCause.description, 1600),
      confidence: sourceRootCause.confidence,
      suspected_paths: sourceRootCause.flow_point ?
        [clipped((sourceRootCause.flow_point as Record<string, unknown>).path, 160)] :
        limited(sourceRootCause.suspected_paths, 12, 160),
      evidence_refs: limited(sourceRootCause.evidence_refs, 20, 128) } : null;
    const sourceTask = investigation.payload.task as Record<string, unknown> | undefined;
    const task = sourceTask ? { title: clipped(sourceTask.title, 240), kind: sourceTask.kind,
      priority: sourceTask.priority,
      acceptance_invariants: limited(sourceTask.acceptance_invariants, 8, 320),
      do_not_break: limited(sourceTask.do_not_break, 8, 320),
      regression_test_ids: limited(sourceTask.regression_test_ids, 16, 128) } : null;
    const payload = { incidentId, taskId, attemptNo,
      incidentMap: mapped?.payload ?? { timeline: Array.isArray(investigation.payload.timeline) ?
        investigation.payload.timeline.slice(0, 8) : [],
        affected_entities: Array.isArray(investigation.payload.affected_entities) ?
          investigation.payload.affected_entities.slice(0, 16) : [],
        containment_actions: Array.isArray(investigation.payload.containment_actions) ?
          investigation.payload.containment_actions.slice(0, 4) : [] },
      rootCause, task, attempts,
      doNotRepeat: attempts.filter((entry) => entry.kind === "dossier.rejection_report" ||
        entry.kind === "ci.failure" || entry.kind === "deploy.rolled_back")
        .map((entry) => entry.summary).slice(-8) };
    const fallback = { incidentId, taskId, attemptNo,
      rootCause: rootCause ? { ...rootCause,
        description: clipped(rootCause.description, 800),
        evidence_refs: limited(rootCause.evidence_refs, 8, 64) } : null,
      task,
      incidentMap: mapped?.payload ? { scope: mapped.payload.scope,
        timeline: Array.isArray(mapped.payload.timeline) ?
          mapped.payload.timeline.slice(0, 3).map((item) => {
            const row = item as Record<string, unknown>;
            return { ts: clipped(row.ts, 40), event_ref: clipped(row.event_ref, 64),
              observation: clipped(row.observation, 120) };
          }) : [],
        entities: Array.isArray(mapped.payload.entities) ?
          mapped.payload.entities.slice(0, 4).map((item) => {
            const row = item as Record<string, unknown>;
            return { kind: clipped(row.kind, 40), id: clipped(row.id, 64) };
          }) : [],
        indicators: Array.isArray(mapped.payload.indicators) ?
          mapped.payload.indicators.slice(0, 3).map((item) => {
            const row = item as Record<string, unknown>;
            return { kind: row.kind, ref: clipped(row.ref, 64),
              evidence_refs: limited(row.evidence_refs, 2, 64) };
          }) : [],
        evidence_refs: limited(mapped.payload.evidence_refs, 6, 64) } :
        { timeline: [], affected_entities: [], containment_actions: [] },
      attempts: attempts.slice(-16).map((item) => ({ ...item,
        summary: clipped(item.summary, 200) })),
      doNotRepeat: payload.doNotRepeat.slice(-4).map((item) => clipped(item, 200)),
      context_truncated: true };
    return this.package(payload, ["incident_map", "root_cause", "task", "previous_attempts"], fallback);
  }

  builderContext(incidentId: string, taskId: string, attemptNo: number): CaseContext {
    const entries = this.history(incidentId);
    const verified = latest(entries, (entry) => entry.kind === "task.verified" &&
      entry.payload.task_id === taskId);
    const investigation = latest(entries, (entry) => entry.kind === "dossier.investigation" &&
      (entry.payload.task as Record<string, unknown> | undefined)?.title === verified?.payload.title);
    const task = investigation?.payload.task;
    if (!verified || !task || typeof task !== "object") throw new Error("CASE_TASK_MISSING");
    const source = task as Record<string, unknown>;
    const boundedTask = { title: clipped(source.title, 240), kind: source.kind,
      priority: source.priority,
      acceptance_invariants: limited(source.acceptance_invariants, 16, 320),
      do_not_break: limited(source.do_not_break, 16, 320),
      regression_test_ids: limited(source.regression_test_ids, 24, 128),
      source_sha256: IncidentCaseFile.digest(source) };
    const design = latest(entries, (entry) => entry.kind === "dossier.fix_design" &&
      entry.payload.task_id === taskId && entry.attempt_no === attemptNo);
    if (!design) throw new Error("CASE_FIX_DESIGN_MISSING");
    const feedback = entries.flatMap((entry) => {
      if (entry.kind === "ci.failure" && entry.payload.task_id === taskId &&
        entry.id > design.id && entry.attempt_no === attemptNo)
        return [`CI ${String(entry.payload.red_first)}; typecheck ${String(entry.payload.typecheck)}; ` +
          `world tests ${String(entry.payload.world_tests)}: ${clipped(entry.payload.failure_output, 900)}`];
      return [];
    }).slice(-8);
    return this.package({ task: boundedTask, taskId, fixDesign: design.payload,
      allowedPaths: design.payload.allowed_paths, priorRejections: feedback,
      attemptNo },
      ["fix_design", "allowed_paths", "same_design_ci_feedback"],
    { task: { title: clipped(source.title, 160), kind: source.kind, priority: source.priority,
      acceptance_invariants: limited(source.acceptance_invariants, 6, 320),
      do_not_break: limited(source.do_not_break, 6, 320),
      regression_test_ids: limited(source.regression_test_ids, 12, 80),
      source_sha256: IncidentCaseFile.digest(source) }, taskId,
      fixDesign: design.payload, allowedPaths: design.payload.allowed_paths,
      priorRejections: feedback.slice(-4).map((item) => clipped(item, 256)), attemptNo });
  }

  reviewerContext(incidentId: string, taskId: string, attemptNo: number): CaseContext {
    const entries = this.history(incidentId);
    const verified = latest(entries, (entry) => entry.kind === "task.verified" &&
      entry.payload.task_id === taskId);
    const investigation = latest(entries, (entry) => entry.kind === "dossier.investigation" &&
      (entry.payload.task as Record<string, unknown> | undefined)?.title === verified?.payload.title);
    const candidate = latest(entries, (entry) => entry.kind === "dossier.candidate" &&
      entry.attempt_no === attemptNo && entry.payload.task_id === taskId);
    const ci = latest(entries, (entry) => entry.kind === "ci.result" &&
      entry.attempt_no === attemptNo && entry.payload.task_id === taskId);
    const design = latest(entries, (entry) => entry.kind === "dossier.fix_design" &&
      entry.attempt_no === attemptNo && entry.payload.task_id === taskId);
    const ciRunId = ci?.payload.run_id;
    if (!verified || !investigation || !candidate || !design || typeof ciRunId !== "string")
      throw new Error("CASE_REVIEW_CONTEXT_MISSING");
    const task = investigation.payload.task as Record<string, unknown>;
    const patch = candidate.payload;
    const changes = Array.isArray(patch.changes) ? patch.changes.slice(0, 16).map((item) => {
      const change = item as Record<string, unknown>;
      return { path: clipped(change.path, 240), lines_changed: change.lines_changed };
    }) : [];
    const priorRejections = entries.filter((entry) => entry.kind === "dossier.review" &&
      entry.payload.task_id === taskId && entry.payload.verdict === "reject")
      .flatMap((entry) => limited(entry.payload.reasons_for_rejection, 8, 400)).slice(-12);
    return this.package({ fixDesign: design.payload, priorRejections,
      patch: { task_id: patch.task_id, attempt_no: patch.attempt_no,
      branch: clipped(patch.branch, 160), head_sha: patch.head_sha,
      changes,
      source_sha256: IncidentCaseFile.digest(patch) }, ciRunId,
      acceptanceInvariants: limited(task.acceptance_invariants, 16, 320),
      doNotBreak: limited(task.do_not_break, 16, 320) },
    ["candidate", "fix_design", "ci_result", "acceptance_invariants", "review_history"],
    { fixDesign: design.payload, priorRejections: priorRejections.slice(-4),
      patch: { task_id: patch.task_id, attempt_no: patch.attempt_no,
      head_sha: patch.head_sha, branch: clipped(patch.branch, 120),
      changes: changes.slice(0, 3).map((change) => ({ path: change.path,
        lines_changed: change.lines_changed })),
      source_sha256: IncidentCaseFile.digest(patch) }, ciRunId,
      acceptanceInvariants: limited(task.acceptance_invariants, 8, 320),
      doNotBreak: limited(task.do_not_break, 8, 320) });
  }

  static digest(payload: unknown): string {
    return createHash("sha256").update(JSON.stringify(payload)).digest("hex");
  }
}
