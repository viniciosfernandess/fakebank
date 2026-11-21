import { createHash } from "node:crypto";
import { closeSync, existsSync, openSync, unlinkSync } from "node:fs";
import { resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath } from "node:url";
import { verifySplitSnapshots } from "./verify-split-snapshot.mjs";

const ECOSYSTEM_TABLE = /^(?:spi_|psp_|dict_)/;

function identifier(value) {
  return `"${value.replaceAll('"', '""')}"`;
}

function tableDigest(db, table, label) {
  const columns = db.prepare(`PRAGMA table_info(${identifier(table)})`).all();
  if (columns.length === 0) throw new Error(`${label}_TABLE_EMPTY_SCHEMA:${table}`);
  const order = columns.filter((column) => column.pk > 0)
    .sort((left, right) => left.pk - right.pk).map((column) => column.name);
  if (order.length === 0) order.push(...columns.map((column) => column.name));
  const hash = createHash("sha256");
  let count = 0;
  const query = `SELECT * FROM ${identifier(table)} ORDER BY ${order.map(identifier).join(",")}`;
  for (const row of db.prepare(query).iterate()) {
    const encoded = JSON.stringify(row, (_key, value) =>
      typeof value === "bigint" ? { bigint: value.toString() } : value);
    hash.update(Buffer.from(String(Buffer.byteLength(encoded)) + ":" + encoded));
    count++;
  }
  return { count, sha256: hash.digest("hex") };
}

function copyOwnedSnapshot(source, sourceFile, outputFile, owner) {
  const label = owner === "bank" ? "BANK" : "ECOSYSTEM";
  let target;
  let created = false;
  try {
    const tables = source.prepare(`SELECT name,sql FROM sqlite_master
      WHERE type='table' AND sql IS NOT NULL ORDER BY name`).all()
      .filter((entry) => !entry.name.startsWith("sqlite_") &&
        entry.name !== "dict_rate_buckets" &&
        (ECOSYSTEM_TABLE.test(entry.name) === (owner === "ecosystem")));
    const required = owner === "ecosystem" ? ["spi_participants", "psp_accounts"] :
      ["accounts", "ledger_entries", "pix_transfers"];
    if (required.some((name) => !tables.some((entry) => entry.name === name)))
      throw new Error(`${label}_SOURCE_INCOMPLETE`);
    const names = new Set(tables.map((entry) => entry.name));
    for (const table of tables) {
      const references = source.prepare(`PRAGMA foreign_key_list(${identifier(table.name)})`).all();
      for (const reference of references)
        if (!names.has(reference.table))
          throw new Error(`${label}_CROSS_BOUNDARY_FK:${table.name}:${reference.table}`);
    }
    const objects = source.prepare(`SELECT type,name,tbl_name,sql FROM sqlite_master
      WHERE type IN ('index','trigger') AND sql IS NOT NULL ORDER BY type,name`).all()
      .filter((entry) => names.has(entry.tbl_name));
    closeSync(openSync(outputFile, "wx", 0o600));
    created = true;
    target = new DatabaseSync(outputFile);
    target.exec("PRAGMA foreign_keys=OFF; BEGIN IMMEDIATE");
    for (const table of tables) target.exec(table.sql);
    for (const table of tables) {
      const columns = source.prepare(`PRAGMA table_info(${identifier(table.name)})`).all()
        .map((column) => column.name);
      const placeholders = columns.map(() => "?").join(",");
      const insert = target.prepare(`INSERT INTO ${identifier(table.name)}
        (${columns.map(identifier).join(",")}) VALUES (${placeholders})`);
      for (const row of source.prepare(`SELECT * FROM ${identifier(table.name)}`).iterate())
        insert.run(...columns.map((column) => row[column]));
    }
    for (const object of objects) target.exec(object.sql);
    if (owner === "bank" && source.prepare(`SELECT 1 FROM sqlite_master
      WHERE type='table' AND name='dict_rate_buckets'`).get()) {
      target.exec(`CREATE TABLE pix_lookup_rate_buckets (
        scope TEXT NOT NULL CHECK(scope IN ('user','participant')),
        subject_hash TEXT NOT NULL, tokens REAL NOT NULL,
        updated_at_ms INTEGER NOT NULL,
        PRIMARY KEY(scope,subject_hash)
      )`);
      const insert = target.prepare(`INSERT INTO pix_lookup_rate_buckets
        (scope,subject_hash,tokens,updated_at_ms) VALUES (?,?,?,?)`);
      for (const row of source.prepare(`SELECT scope,subject_hash,tokens,updated_at_ms
        FROM dict_rate_buckets`).iterate())
        insert.run(row.scope, row.subject_hash, row.tokens, row.updated_at_ms);
    }
    target.exec("COMMIT; PRAGMA foreign_keys=ON");
    const fkErrors = target.prepare("PRAGMA foreign_key_check").all();
    if (fkErrors.length) throw new Error(`${label}_FOREIGN_KEY_INVALID`);
    const integrity = target.prepare("PRAGMA integrity_check").all();
    if (integrity.length !== 1 || integrity[0].integrity_check !== "ok")
      throw new Error(`${label}_INTEGRITY_INVALID`);
    const manifest = {};
    for (const table of tables) {
      const expected = tableDigest(source, table.name, label);
      const actual = tableDigest(target, table.name, label);
      if (expected.count !== actual.count || expected.sha256 !== actual.sha256)
        throw new Error(`${label}_COPY_MISMATCH:${table.name}`);
      manifest[table.name] = expected;
    }
    if (owner === "bank" && target.prepare(`SELECT 1 FROM sqlite_master
      WHERE type='table' AND name='pix_lookup_rate_buckets'`).get()) {
      const expected = tableDigest(source, "dict_rate_buckets", label);
      const actual = tableDigest(target, "pix_lookup_rate_buckets", label);
      if (expected.count !== actual.count || expected.sha256 !== actual.sha256)
        throw new Error("BANK_COPY_MISMATCH:pix_lookup_rate_buckets");
      manifest.pix_lookup_rate_buckets = expected;
    }
    return { source: sourceFile, output: outputFile, tables: manifest };
  } catch (error) {
    if (target?.isTransaction) target.exec("ROLLBACK");
    target?.close();
    target = undefined;
    if (created) unlinkSync(outputFile);
    throw error;
  } finally {
    target?.close();
  }
}

function migrateLegacyOpenMed(bankPath, ecosystemPath) {
  const bank = new DatabaseSync(bankPath);
  const ecosystem = new DatabaseSync(ecosystemPath);
  let migrated = 0;
  try {
    bank.exec("PRAGMA foreign_keys=ON; BEGIN IMMEDIATE");
    ecosystem.exec("PRAGMA foreign_keys=ON; BEGIN IMMEDIATE");
    ecosystem.exec(`CREATE TABLE IF NOT EXISTS psp_med_case_openings (
      case_id TEXT PRIMARY KEY, root_transfer_id TEXT NOT NULL UNIQUE
        REFERENCES psp_roots(root_transfer_id),
      claim_amount_cents INTEGER NOT NULL CHECK(claim_amount_cents>0),
      created_at TEXT NOT NULL
    );
    CREATE TRIGGER IF NOT EXISTS psp_med_case_openings_no_update
      BEFORE UPDATE ON psp_med_case_openings
      BEGIN SELECT RAISE(ABORT,'PSP_MED_OPEN_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS psp_med_case_openings_no_delete
      BEFORE DELETE ON psp_med_case_openings
      BEGIN SELECT RAISE(ABORT,'PSP_MED_OPEN_IMMUTABLE'); END;`);
    const cases = bank.prepare(`SELECT m.id,m.transfer_id,m.opened_at,
      m.claim_amount_cents,p.end_to_end_id
      FROM med_cases m JOIN pix_transfers p ON p.id=m.transfer_id
      WHERE m.status='open' AND NOT EXISTS
        (SELECT 1 FROM accounts a WHERE a.id=p.to_account)
      ORDER BY m.id`).all();
    for (const med of cases) {
      const claim = med.claim_amount_cents;
      const root = ecosystem.prepare(`SELECT end_to_end_id FROM psp_roots
        WHERE root_transfer_id=?`).get(med.transfer_id);
      if (!Number.isSafeInteger(claim) || claim <= 0 ||
        root?.end_to_end_id !== med.end_to_end_id)
        throw new Error(`SPLIT_LEGACY_MED_INVALID:${med.id}`);
      const bankHops = bank.prepare(`SELECT id,account_id,blocked_cents,
        refunded_cents,created_at,released_at FROM med_hops
        WHERE case_id=? ORDER BY id`).all(med.id);
      const pspHops = ecosystem.prepare(`SELECT hop_id id,account_id,blocked_cents,
        refunded_cents,created_at,released_at FROM psp_med_holds
        WHERE case_id=? AND root_transfer_id=? ORDER BY hop_id`)
        .all(med.id, med.transfer_id);
      if (bankHops.length !== pspHops.length || bankHops.some((hop, index) =>
        ["id", "account_id", "blocked_cents", "refunded_cents", "created_at",
          "released_at"].some((field) => hop[field] !== pspHops[index]?.[field]) ||
        hop.refunded_cents !== 0 || hop.released_at !== null))
        throw new Error(`SPLIT_LEGACY_MED_HOPS_INVALID:${med.id}`);
      const existing = bank.prepare(`SELECT transfer_id,claim_amount_cents,
        created_at,acknowledged_at FROM med_psp_open_outbox WHERE case_id=?`)
        .get(med.id);
      if (existing && (existing.transfer_id !== med.transfer_id ||
        existing.claim_amount_cents !== claim || !existing.acknowledged_at))
        throw new Error(`SPLIT_LEGACY_MED_OPEN_INVALID:${med.id}`);
      const createdAt = existing?.created_at ?? med.opened_at;
      if (!existing) {
        bank.prepare(`INSERT INTO med_psp_open_outbox
          (case_id,transfer_id,claim_amount_cents,created_at,acknowledged_at)
          VALUES (?,?,?,?,?)`).run(med.id, med.transfer_id, claim, createdAt, createdAt);
        migrated++;
      }
      const worker = ecosystem.prepare(`SELECT root_transfer_id,claim_amount_cents,
        created_at FROM psp_med_case_openings WHERE case_id=?`).get(med.id);
      if (worker && (worker.root_transfer_id !== med.transfer_id ||
        worker.claim_amount_cents !== claim || worker.created_at !== createdAt))
        throw new Error(`SPLIT_LEGACY_MED_OPEN_INVALID:${med.id}`);
      if (!worker) ecosystem.prepare(`INSERT INTO psp_med_case_openings
        (case_id,root_transfer_id,claim_amount_cents,created_at) VALUES (?,?,?,?)`)
        .run(med.id, med.transfer_id, claim, createdAt);
    }
    bank.exec("COMMIT");
    ecosystem.exec("COMMIT");
    return { migrated,
      bankOpenOutbox: tableDigest(bank, "med_psp_open_outbox", "BANK"),
      ecosystemOpenings: tableDigest(ecosystem, "psp_med_case_openings", "ECOSYSTEM") };
  } catch (error) {
    if (bank.isTransaction) bank.exec("ROLLBACK");
    if (ecosystem.isTransaction) ecosystem.exec("ROLLBACK");
    throw error;
  } finally { ecosystem.close(); bank.close(); }
}

function exportOwnedSnapshot(sourcePath, outputPath, owner) {
  const label = owner === "bank" ? "BANK" : "ECOSYSTEM";
  const sourceFile = resolve(sourcePath);
  const outputFile = resolve(outputPath);
  if (sourceFile === outputFile || !existsSync(sourceFile))
    throw new Error(`${label}_SOURCE_INVALID`);
  if (existsSync(outputFile)) throw new Error(`${label}_OUTPUT_EXISTS`);
  const source = new DatabaseSync(sourceFile, { readOnly: true });
  try {
    source.exec("BEGIN");
    const result = copyOwnedSnapshot(source, sourceFile, outputFile, owner);
    source.exec("COMMIT");
    return result;
  } catch (error) {
    if (source.isTransaction) source.exec("ROLLBACK");
    throw error;
  } finally { source.close(); }
}

export function exportEcosystemSnapshot(sourcePath, outputPath) {
  return exportOwnedSnapshot(sourcePath, outputPath, "ecosystem");
}

export function exportBankSnapshot(sourcePath, outputPath) {
  return exportOwnedSnapshot(sourcePath, outputPath, "bank");
}

export function exportSplitSnapshots(sourcePath, bankOutputPath, ecosystemOutputPath) {
  const sourceFile = resolve(sourcePath);
  const bankFile = resolve(bankOutputPath);
  const ecosystemFile = resolve(ecosystemOutputPath);
  if (!existsSync(sourceFile) || new Set([sourceFile, bankFile, ecosystemFile]).size !== 3)
    throw new Error("SPLIT_SNAPSHOT_PATH_INVALID");
  if (existsSync(bankFile) || existsSync(ecosystemFile))
    throw new Error("SPLIT_SNAPSHOT_OUTPUT_EXISTS");
  const source = new DatabaseSync(sourceFile, { readOnly: true });
  let bank;
  let ecosystem;
  try {
    source.exec("BEGIN");
    bank = copyOwnedSnapshot(source, sourceFile, bankFile, "bank");
    ecosystem = copyOwnedSnapshot(source, sourceFile, ecosystemFile, "ecosystem");
    const medMigration = migrateLegacyOpenMed(bankFile, ecosystemFile);
    bank.tables.med_psp_open_outbox = medMigration.bankOpenOutbox;
    ecosystem.tables.psp_med_case_openings = medMigration.ecosystemOpenings;
    const reconciliation = verifySplitSnapshots(bankFile, ecosystemFile);
    if (!reconciliation.ok)
      throw new Error("SPLIT_SNAPSHOT_RECONCILIATION_FAILED");
    source.exec("COMMIT");
    return { source: sourceFile, bank, ecosystem, medMigration: {
      migrated: medMigration.migrated }, reconciliation };
  } catch (error) {
    if (source.isTransaction) source.exec("ROLLBACK");
    if (bank) unlinkSync(bankFile);
    if (ecosystem) unlinkSync(ecosystemFile);
    throw error;
  } finally { source.close(); }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  if (process.argv.length !== 4) {
    process.stderr.write("Usage: node scripts/export-ecosystem-snapshot.mjs <bank.sqlite> <ecosystem.sqlite>\n");
    process.exitCode = 2;
  } else {
    try {
      const result = exportEcosystemSnapshot(process.argv[2], process.argv[3]);
      process.stdout.write(JSON.stringify(result) + "\n");
    } catch (error) {
      process.stderr.write(`${error.message}\n`);
      process.exitCode = 1;
    }
  }
}
