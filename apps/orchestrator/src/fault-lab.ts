import { randomUUID } from "node:crypto";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";

export type FaultId = "auth_event_silence" | "gateway_heartbeat_silence" |
  "statement_unavailable" | "loan_offer_unavailable" |
  "pix_automatic_mandates_unavailable" | "automatic_pix_execution_delayed" |
  "kyc_status_unavailable" | "kyc_submission_unavailable" | "kyc_review_interrupted" |
  "revoked_device_access" | "risk_false_hold" |
  "risk_missed_hold" |
  "pix_dispatch_paused" | "card_issuer_offline" | "spi_unavailable" |
  "psp_receipt_delayed" | "med_opening_delayed" | "med_analysis_delayed" |
  "med_settlement_delayed" | "med_release_delayed" |
  "hourly_proof_paused" | "fee_rounding_drift";
export type FaultDomain = "security" | "fraud" | "operation" | "integrity";
export type FaultRunStatus = "arming" | "injecting" | "observed" |
  "stopped" | "expired" | "failed" | "cleanup_failed";
export type FaultResultState = "pending" | "observed" | "not_observed";

export interface FaultCatalogItem {
  id: FaultId; label: string; domain: FaultDomain; description: string;
  available: boolean; incompatible_with: FaultId[];
}
export interface FaultPreview {
  compatible: boolean; reasons: string[]; selected: FaultCatalogItem[];
  scope: { mode: "disposable_local"; max_faults: number; max_duration_ms: number };
}
export interface FaultTimelineEntry {
  at: string; stage: "armed" | "injection_started" | "probe_completed" |
    "probe_failed" | "symptom_observed" | "stopped" | "expired" | "failed";
  fixture_id?: FaultId; detail: string;
}
export interface FaultRunPublic {
  id: string; status: FaultRunStatus; selected_ids: FaultId[];
  started_at: string; stopped_at: string | null; expires_at: string;
  timeline: FaultTimelineEntry[];
  results: { fixture_id: FaultId; state: FaultResultState; evidence_refs: string[] }[];
}
export interface FaultObservation { observed: boolean; evidence_refs: string[] }
export interface FaultAdapter {
  /** Dynamic guard for a fault that cannot be safely rearmed yet. */
  available?(): boolean;
  /** Idempotent: the call can be repeated after a crash. */
  start(input: { runId: string; startedAt: string; expiresAt: string }): void | Promise<void>;
  /** Reapply a run-owned in-memory seam after a process restart. */
  resume?(input: { runId: string; startedAt: string; expiresAt: string }): void | Promise<void>;
  /** Idempotent and run-owned; stop even if the activation receipt was lost. */
  stop(input: { runId: string; startedAt: string }): void | Promise<void>;
  /** Inspect a real symptom, not the injector acknowledgement. */
  observe(input: { runId: string; startedAt: string }): FaultObservation |
    Promise<FaultObservation>;
}
export class FaultLabError extends Error {
  readonly code: string;
  constructor(code: string) { super(code); this.code = code; }
}

const CATALOG: readonly Omit<FaultCatalogItem, "available">[] = [
  { id: "auth_event_silence", label: "Eventos de acesso param de chegar",
    domain: "security", description: "Verifica se a fonte de autenticação fica silenciosa",
    incompatible_with: [] },
  { id: "gateway_heartbeat_silence", label: "Sinal do gateway para de chegar",
    domain: "security", description: "Verifica se o Sentinela detecta a falta do sinal de saúde do gateway",
    incompatible_with: [] },
  { id: "statement_unavailable", label: "Extrato fica indisponível",
    domain: "operation", description: "Um cliente sintético não consegue consultar o próprio extrato até a recuperação",
    incompatible_with: [] },
  { id: "loan_offer_unavailable", label: "Oferta de crédito fica indisponível",
    domain: "operation", description: "Um cliente sintético não consegue consultar sua oferta de crédito até a recuperação",
    incompatible_with: [] },
  { id: "pix_automatic_mandates_unavailable", label: "Autorizações de Pix Automático ficam indisponíveis",
    domain: "operation", description: "Um cliente sintético não consegue consultar suas autorizações de Pix Automático até a recuperação",
    incompatible_with: [] },
  { id: "automatic_pix_execution_delayed", label: "Cobrança de Pix Automático atrasa",
    domain: "operation", description: "Atrasa uma cobrança autorizada que está prestes a vencer no banco sintético",
    incompatible_with: [] },
  { id: "kyc_status_unavailable", label: "Consulta da verificação de identidade indisponível",
    domain: "operation", description: "Um cliente sintético não consegue consultar o estado da própria verificação de identidade",
    incompatible_with: [] },
  { id: "kyc_submission_unavailable", label: "Envio da verificação de identidade indisponível",
    domain: "operation", description: "Um cliente sintético não consegue enviar uma solicitação assinada de verificação de identidade",
    incompatible_with: [] },
  { id: "kyc_review_interrupted", label: "Revisão de identidade interrompida",
    domain: "operation", description: "Cria uma solicitação sintética e interrompe sua aprovação autenticada até o fim da falha",
    incompatible_with: [] },
  { id: "revoked_device_access", label: "Acesso após revogação simulado",
    domain: "security", description: "Reproduz uma consulta fictícia sem dados de conta para o Sentinela de identidade e mantém o aparelho bloqueado",
    incompatible_with: [] },
  { id: "risk_false_hold", label: "Pix legítimo é retido",
    domain: "fraud", description: "Mede falso bloqueio e reparação do cliente",
    incompatible_with: ["risk_missed_hold"] },
  { id: "risk_missed_hold", label: "Pix sem retenção simulado",
    domain: "fraud", description: "Apresenta um histórico fictício de Pix ao Sentinela sem desligar a retenção preventiva",
    incompatible_with: ["risk_false_hold"] },
  { id: "pix_dispatch_paused", label: "Fila Pix fica atrasada",
    domain: "operation", description: "Mostra pagamento pendente e retomada sem duplicidade",
    incompatible_with: ["spi_unavailable", "psp_receipt_delayed"] },
  { id: "card_issuer_offline", label: "Emissor de cartão indisponível",
    domain: "operation", description: "Autorização de cartão recebe resposta de indisponibilidade",
    incompatible_with: [] },
  { id: "spi_unavailable", label: "SPI indisponível",
    domain: "operation", description: "Pix entre instituições permanece recuperável",
    incompatible_with: ["pix_dispatch_paused", "psp_receipt_delayed"] },
  { id: "psp_receipt_delayed", label: "Recibo do PSP atrasa",
    domain: "integrity", description: "Conciliação entre livros permanece pendente",
    incompatible_with: ["spi_unavailable", "pix_dispatch_paused"] },
  { id: "med_opening_delayed", label: "Abertura da contestação Pix fica atrasada",
    domain: "integrity", description: "A contestação aguarda confirmação do PSP antes de entrar em análise",
    incompatible_with: ["spi_unavailable", "pix_dispatch_paused", "psp_receipt_delayed"] },
  { id: "med_analysis_delayed", label: "Análise da contestação Pix no DICT atrasa",
    domain: "integrity",
    description: "Atrasa a confirmação do DICT após a aprovação por dois operadores na fila do MED",
    incompatible_with: ["spi_unavailable", "pix_dispatch_paused", "psp_receipt_delayed",
      "med_opening_delayed"] },
  { id: "med_settlement_delayed", label: "Liquidação da contestação Pix atrasa",
    domain: "integrity", description: "Atrasa a restituição da contestação aprovada na fila do MED",
    incompatible_with: ["spi_unavailable", "pix_dispatch_paused", "psp_receipt_delayed",
      "med_opening_delayed", "med_analysis_delayed"] },
  { id: "med_release_delayed", label: "Liberação após rejeição da contestação Pix atrasa",
    domain: "integrity", description: "Atrasa a liberação da retenção da contestação rejeitada na fila do MED",
    incompatible_with: ["spi_unavailable", "pix_dispatch_paused", "psp_receipt_delayed",
      "med_opening_delayed", "med_analysis_delayed", "med_settlement_delayed"] },
  { id: "hourly_proof_paused", label: "Prova periódica não aparece",
    domain: "integrity", description: "Prazo da prova revela o silêncio da fonte",
    incompatible_with: [] },
  { id: "fee_rounding_drift", label: "Tarifa gera diferença contábil",
    domain: "integrity", description: "Cobranças sintéticas revelam um defeito de arredondamento",
    incompatible_with: [] },
];
const IDS = new Set<FaultId>(CATALOG.map((item) => item.id));
const ACTIVE: readonly FaultRunStatus[] = ["arming", "injecting", "observed",
  "cleanup_failed"];
const MAX_FAULTS = 4;
const MAX_DURATION_MS = 120_000;
const PAYMENT_QUEUE_DURATION_MS = 40_000;
const durationFor = (ids: readonly string[]): number =>
  ids.some((id) => id === "pix_dispatch_paused" || id === "spi_unavailable") ?
    PAYMENT_QUEUE_DURATION_MS : MAX_DURATION_MS;
type RunRow = { id: string; status: FaultRunStatus; selected_json: string;
  started_at: string; stopped_at: string | null; expires_at: string };
type FixtureRow = { fixture_id: FaultId; applied_at: string | null;
  observed_at: string | null; evidence_json: string };

export class FaultLab {
  readonly db: DatabaseSync;
  private readonly adapters: Partial<Record<FaultId, FaultAdapter>>;
  private readonly now: () => Date;
  private readonly maxConcurrentRuns: number;
  private busy = false;

  constructor(input: { dbPath: string;
    adapters: Partial<Record<FaultId, FaultAdapter>>;
    now?: () => Date; maxConcurrentRuns?: number }) {
    if (!input.dbPath?.endsWith(".sqlite"))
      throw new FaultLabError("FAULT_LAB_PATH_INVALID");
    if (input.maxConcurrentRuns !== undefined &&
      (!Number.isSafeInteger(input.maxConcurrentRuns) ||
        input.maxConcurrentRuns < 1 || input.maxConcurrentRuns > 3))
      throw new FaultLabError("FAULT_LAB_CONCURRENCY_INVALID");
    mkdirSync(dirname(input.dbPath), { recursive: true });
    this.db = new DatabaseSync(input.dbPath);
    this.db.exec("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=1000;");
    this.db.exec(`CREATE TABLE IF NOT EXISTS fault_lab_runs (
      id TEXT PRIMARY KEY, status TEXT NOT NULL, selected_json TEXT NOT NULL,
      started_at TEXT NOT NULL, stopped_at TEXT, expires_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS fault_lab_fixtures (
      run_id TEXT NOT NULL REFERENCES fault_lab_runs(id), fixture_id TEXT NOT NULL,
      applied_at TEXT, observed_at TEXT, evidence_json TEXT NOT NULL,
      PRIMARY KEY(run_id,fixture_id)
    );
    CREATE TABLE IF NOT EXISTS fault_lab_timeline (
      seq INTEGER PRIMARY KEY, run_id TEXT NOT NULL REFERENCES fault_lab_runs(id),
      at TEXT NOT NULL, stage TEXT NOT NULL, fixture_id TEXT, detail TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS fault_lab_timeline_run ON fault_lab_timeline(run_id,seq);
    CREATE TRIGGER IF NOT EXISTS fault_lab_timeline_no_update BEFORE UPDATE
      ON fault_lab_timeline BEGIN SELECT RAISE(ABORT,'FAULT_LAB_TIMELINE_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS fault_lab_timeline_no_delete BEFORE DELETE
      ON fault_lab_timeline BEGIN SELECT RAISE(ABORT,'FAULT_LAB_TIMELINE_IMMUTABLE'); END;`);
    this.adapters = input.adapters;
    this.now = input.now ?? (() => new Date());
    this.maxConcurrentRuns = input.maxConcurrentRuns ?? 1;
  }

  catalog(): FaultCatalogItem[] {
    return CATALOG.map((item) => ({ ...item,
      incompatible_with: [...item.incompatible_with],
      available: Boolean(this.adapters[item.id] &&
        (this.adapters[item.id]?.available?.() ?? true)) }));
  }
  preview(requested: string[]): FaultPreview {
    if (!Array.isArray(requested))
      throw new FaultLabError("FAULT_LAB_SELECTION_INVALID");
    if (requested.length > MAX_FAULTS * 2)
      throw new FaultLabError("FAULT_LAB_SELECTION_TOO_LARGE");
    const reasons: string[] = [];
    const unique = new Set<string>();
    for (const id of requested) {
      if (typeof id !== "string" || !IDS.has(id as FaultId))
        throw new FaultLabError("FAULT_LAB_FIXTURE_UNKNOWN");
      if (unique.has(id)) reasons.push("duplicate_fixture");
      unique.add(id);
    }
    if (!unique.size) reasons.push("empty_selection");
    if (unique.size > MAX_FAULTS) reasons.push("too_many_fixtures");
    const selected = this.catalog().filter((item) => unique.has(item.id));
    for (const item of selected) {
      if (!item.available) reasons.push(`unavailable:${item.id}`);
      const inUse = this.db.prepare(`SELECT 1 FROM fault_lab_fixtures f
        JOIN fault_lab_runs r ON r.id=f.run_id
        WHERE f.fixture_id=? AND r.status IN
          ('arming','injecting','observed','cleanup_failed') LIMIT 1`)
        .get(item.id);
      if (inUse) reasons.push(`fixture_in_use:${item.id}`);
      for (const other of item.incompatible_with)
        if (unique.has(other) && item.id < other)
          reasons.push(`incompatible:${item.id}:${other}`);
    }
    const active = this.db.prepare(`SELECT COUNT(*) n FROM fault_lab_runs
      WHERE status IN ('arming','injecting','observed','cleanup_failed')`).get() as { n: number };
    if (active.n >= this.maxConcurrentRuns) reasons.push("active_run_limit");
    return { compatible: reasons.length === 0, reasons, selected,
      scope: { mode: "disposable_local", max_faults: MAX_FAULTS,
        max_duration_ms: durationFor([...unique]) } };
  }
  run(runId: string): FaultRunPublic | undefined {
    const row = this.row(runId);
    if (!row) return undefined;
    const fixtures = this.fixtures(runId);
    const timelineRows = this.db.prepare(`SELECT at,stage,fixture_id,detail
      FROM fault_lab_timeline WHERE run_id=? ORDER BY seq`)
      .all(runId) as unknown as (Omit<FaultTimelineEntry, "fixture_id"> & {
        fixture_id: FaultId | null })[];
    const timeline = timelineRows.map(({ fixture_id, ...entry }) =>
      fixture_id ? { ...entry, fixture_id } : entry);
    return { id: row.id, status: row.status,
      selected_ids: JSON.parse(row.selected_json) as FaultId[],
      started_at: row.started_at, stopped_at: row.stopped_at,
      expires_at: row.expires_at, timeline,
      results: fixtures.map((fixture) => ({
        fixture_id: fixture.fixture_id,
        state: fixture.observed_at ? "observed" :
          ACTIVE.includes(row.status) ? "pending" : "not_observed",
        evidence_refs: JSON.parse(fixture.evidence_json) as string[],
      })) };
  }
  list(): FaultRunPublic[] {
    const rows = this.db.prepare(`SELECT id FROM fault_lab_runs
      ORDER BY started_at DESC LIMIT 50`).all() as { id: string }[];
    return rows.map((row) => this.run(row.id)!);
  }
  /** For runtime hooks; this private injection state never enters the case packet. */
  active(fixtureId: FaultId, runId?: string): boolean {
    return Boolean(this.db.prepare(`SELECT 1 FROM fault_lab_fixtures f
      JOIN fault_lab_runs r ON r.id=f.run_id
      WHERE f.fixture_id=? AND f.applied_at IS NOT NULL AND (? IS NULL OR r.id=?)
      AND r.status IN ('arming','injecting','observed','cleanup_failed') LIMIT 1`)
      .get(fixtureId, runId ?? null, runId ?? null));
  }
  async start(requested: string[]): Promise<FaultRunPublic> {
    return this.lock(async () => {
      const preview = this.preview(requested);
      if (!preview.compatible)
        throw new FaultLabError(`FAULT_LAB_PREVIEW_REJECTED:${preview.reasons.join(",")}`);
      const now = this.timestamp();
      const runId = randomUUID();
      const expiresAt = new Date(Date.parse(now) +
        durationFor(preview.selected.map((item) => item.id))).toISOString();
      this.db.exec("BEGIN IMMEDIATE");
      try {
        this.db.prepare(`INSERT INTO fault_lab_runs
          (id,status,selected_json,started_at,expires_at)
          VALUES (?,'arming',?,?,?)`)
          .run(runId, JSON.stringify(preview.selected.map((item) => item.id)),
            now, expiresAt);
        for (const item of preview.selected)
          this.db.prepare(`INSERT INTO fault_lab_fixtures
            (run_id,fixture_id,evidence_json) VALUES (?,?,'[]')`)
            .run(runId, item.id);
        this.timeline(runId, now, "armed", null, "Experimento local preparado com limites");
        this.db.exec("COMMIT");
      } catch (error) { this.db.exec("ROLLBACK"); throw error; }
      await this.arm(runId);
      return this.run(runId)!;
    });
  }
  async stop(runId: string): Promise<FaultRunPublic> {
    return this.lock(async () => {
      const row = this.row(runId);
      if (!row) throw new FaultLabError("FAULT_LAB_RUN_NOT_FOUND");
      if (ACTIVE.includes(row.status)) await this.deactivate(row, "stopped");
      return this.run(runId)!;
    });
  }
  /** Record a synthetic ordinary-bank operation without claiming detection. */
  recordProbe(runId: string, fixtureId: FaultId,
    outcome: "completed" | "failed"): void {
    const row = this.row(runId);
    if (!row) throw new FaultLabError("FAULT_LAB_RUN_NOT_FOUND");
    if (!ACTIVE.includes(row.status) || row.status === "cleanup_failed")
      throw new FaultLabError("FAULT_LAB_RUN_NOT_ACTIVE");
    if (!this.fixtures(runId).some((fixture) => fixture.fixture_id === fixtureId))
      throw new FaultLabError("FAULT_LAB_FIXTURE_NOT_SELECTED");
    this.timeline(runId, this.timestamp(),
      outcome === "completed" ? "probe_completed" : "probe_failed",
      fixtureId, outcome === "completed" ?
        "Operação sintética do banco concluída" : "Operação sintética do banco falhou");
  }
  async stopAll(): Promise<void> {
    await this.lock(async () => {
      const rows = this.db.prepare(`SELECT * FROM fault_lab_runs
        WHERE status IN ('arming','injecting','observed','cleanup_failed')`)
        .all() as RunRow[];
      for (const row of rows) await this.deactivate(row, "stopped");
      if (rows.some((row) => this.row(row.id)?.status === "cleanup_failed"))
        throw new FaultLabError("FAULT_LAB_CLEANUP_FAILED");
    });
  }
  async shutdown(): Promise<void> {
    try { await this.stopAll(); }
    finally { this.close(); }
  }
  async tick(): Promise<void> {
    if (this.busy) return;
    await this.lock(async () => {
      const rows = this.db.prepare(`SELECT * FROM fault_lab_runs
        WHERE status IN ('arming','injecting','observed','cleanup_failed')
        ORDER BY started_at`)
        .all() as RunRow[];
      for (const row of rows) {
        if (row.status === "cleanup_failed") {
          await this.deactivate(row, "failed");
          continue;
        }
        if (Date.parse(row.expires_at) <= Date.parse(this.timestamp())) {
          await this.deactivate(row, "expired");
          continue;
        }
        if (row.status === "arming") await this.arm(row.id);
        const current = this.row(row.id);
        if (current && current.status !== "arming" && ACTIVE.includes(current.status)) {
          try {
            for (const fixture of this.fixtures(current.id)) {
              if (!fixture.applied_at) continue;
              await this.adapters[fixture.fixture_id]?.resume?.({
                runId: current.id, startedAt: current.started_at,
                expiresAt: current.expires_at });
            }
            await this.observe(current);
          }
          catch {
            await this.deactivate(current, "failed");
          }
        }
      }
    });
  }
  close(): void { this.db.close(); }

  private async arm(runId: string): Promise<void> {
    const row = this.row(runId);
    if (!row || row.status !== "arming") return;
    try {
      for (const fixture of this.fixtures(runId)) {
        if (fixture.applied_at) continue;
        const adapter = this.adapters[fixture.fixture_id];
        if (!adapter) throw new FaultLabError("FAULT_LAB_ADAPTER_MISSING");
        try {
          await adapter.start({ runId, startedAt: row.started_at,
            expiresAt: row.expires_at });
        } catch (error) {
          try { await adapter.stop({ runId, startedAt: row.started_at }); }
          catch {
            this.db.prepare(`UPDATE fault_lab_fixtures SET applied_at=?
              WHERE run_id=? AND fixture_id=? AND applied_at IS NULL`)
              .run(this.timestamp(), runId, fixture.fixture_id);
          }
          throw error;
        }
        const at = this.timestamp();
        this.db.prepare(`UPDATE fault_lab_fixtures SET applied_at=?
          WHERE run_id=? AND fixture_id=? AND applied_at IS NULL`)
          .run(at, runId, fixture.fixture_id);
        this.timeline(runId, at, "injection_started", fixture.fixture_id,
          "Falha controlada ativada");
      }
      this.db.prepare(`UPDATE fault_lab_runs SET status='injecting'
        WHERE id=? AND status='arming'`).run(runId);
    } catch (error) {
      await this.deactivate(row, "failed");
      throw error;
    }
  }
  private async observe(row: RunRow): Promise<void> {
    for (const fixture of this.fixtures(row.id)) {
      if (fixture.observed_at) continue;
      const adapter = this.adapters[fixture.fixture_id];
      if (!adapter) continue;
      const observed = await adapter.observe({ runId: row.id,
        startedAt: row.started_at });
      if (typeof observed?.observed !== "boolean" ||
        !Array.isArray(observed.evidence_refs) ||
        observed.evidence_refs.some((ref) => typeof ref !== "string" ||
          ref.length < 1 || ref.length > 240))
        throw new FaultLabError("FAULT_LAB_OBSERVATION_INVALID");
      if (!observed.observed || !observed.evidence_refs.length) continue;
      const at = this.timestamp();
      this.db.prepare(`UPDATE fault_lab_fixtures SET observed_at=?,evidence_json=?
        WHERE run_id=? AND fixture_id=? AND observed_at IS NULL`)
        .run(at, JSON.stringify(observed.evidence_refs.slice(0, 20)),
          row.id, fixture.fixture_id);
      this.timeline(row.id, at, "symptom_observed", fixture.fixture_id,
        "Sintoma confirmado no banco ou serviço");
    }
    const missing = this.db.prepare(`SELECT 1 FROM fault_lab_fixtures
      WHERE run_id=? AND observed_at IS NULL LIMIT 1`).get(row.id);
    if (!missing) this.db.prepare(`UPDATE fault_lab_runs SET status='observed'
      WHERE id=? AND status='injecting'`).run(row.id);
  }
  private async deactivate(row: RunRow, target: "stopped" | "expired" | "failed"):
    Promise<void> {
    let failure = false;
    // An adapter may have applied its effect before the applied_at write failed.
    // Every stop is run-scoped and idempotent, so also inspect unrecorded effects.
    for (const fixture of this.fixtures(row.id).reverse()) {
      const adapter = this.adapters[fixture.fixture_id];
      if (!adapter) { failure = true; continue; }
      try { await adapter.stop({ runId: row.id, startedAt: row.started_at }); }
      catch { failure = true; }
    }
    const at = this.timestamp();
    const status = failure ? "cleanup_failed" : target;
    this.db.prepare(`UPDATE fault_lab_runs SET status=?,stopped_at=?
      WHERE id=? AND status IN ('arming','injecting','observed','cleanup_failed')`)
      .run(status, failure ? null : at, row.id);
    this.timeline(row.id, at, failure ? "failed" : target, null,
      failure ? "Falha ao encerrar a injeção; verificar o banco local" :
        target === "expired" ? "Tempo limite da injeção encerrado" :
          target === "stopped" ? "Injeção encerrada; efeitos ainda exigem reparo" :
            "Falha ao ativar a injeção");
  }
  private row(runId: string): RunRow | undefined {
    return this.db.prepare("SELECT * FROM fault_lab_runs WHERE id=?")
      .get(runId) as RunRow | undefined;
  }
  private fixtures(runId: string): FixtureRow[] {
    return this.db.prepare(`SELECT fixture_id,applied_at,observed_at,evidence_json
      FROM fault_lab_fixtures WHERE run_id=? ORDER BY rowid`)
      .all(runId) as FixtureRow[];
  }
  private timestamp(): string {
    const value = this.now();
    if (!Number.isFinite(value.getTime()))
      throw new FaultLabError("FAULT_LAB_CLOCK_INVALID");
    return value.toISOString();
  }
  private timeline(runId: string, at: string, stage: FaultTimelineEntry["stage"],
    fixtureId: FaultId | null, detail: string): void {
    this.db.prepare(`INSERT INTO fault_lab_timeline
      (run_id,at,stage,fixture_id,detail) VALUES (?,?,?,?,?)`)
      .run(runId, at, stage, fixtureId, detail);
  }
  private async lock<T>(work: () => Promise<T>): Promise<T> {
    if (this.busy) throw new FaultLabError("FAULT_LAB_BUSY");
    this.busy = true;
    try { return await work(); }
    finally { this.busy = false; }
  }
}

/** Use a service's ordinary availability control and an independent symptom query. */
export function availabilityFaultAdapter(input: {
  available: () => boolean | Promise<boolean>;
  ownsFailure: (runId: string) => boolean | Promise<boolean>;
  setAvailable: (available: boolean, runId: string) => void | Promise<void>;
  symptom: (startedAt: string, runId: string) => FaultObservation |
    Promise<FaultObservation>;
}): FaultAdapter {
  return {
    async start({ runId }) {
      if (!await input.available()) {
        if (await input.ownsFailure(runId)) return;
        throw new FaultLabError("FAULT_LAB_TARGET_NOT_HEALTHY");
      }
      await input.setAvailable(false, runId);
      if (await input.available()) throw new FaultLabError("FAULT_LAB_EFFECT_NOT_APPLIED");
    },
    async stop({ runId }) {
      if (!await input.ownsFailure(runId)) return;
      if (!await input.available()) await input.setAvailable(true, runId);
      if (!await input.available()) throw new FaultLabError("FAULT_LAB_EFFECT_NOT_REMOVED");
    },
    observe({ startedAt, runId }) { return input.symptom(startedAt, runId); },
  };
}
