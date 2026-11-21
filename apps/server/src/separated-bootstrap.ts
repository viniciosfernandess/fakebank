import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Bank } from "../../world/src/bank.ts";
import { seedBank, type SeedOptions } from "../../world/src/seed.ts";

const EXPORT_SCRIPT = resolve(dirname(fileURLToPath(import.meta.url)),
  "../../../scripts/export-split-snapshot.mjs");

export function ensureSeparatedData(dataDir: string, seed?: SeedOptions): void {
  mkdirSync(dataDir, { recursive: true });
  const bankPath = join(dataDir, "bank.sqlite");
  const ecosystemPath = join(dataDir, "ecosystem.sqlite");
  const hasBank = existsSync(bankPath);
  const hasEcosystem = existsSync(ecosystemPath);
  if (hasBank && hasEcosystem) return;
  if (hasBank || hasEcosystem)
    throw new Error("SEPARATED_DATA_INCOMPLETE: export a frozen combined bank into a new data directory with pnpm export:split-snapshot; existing files were not changed");

  const scratch = mkdtempSync(join(tmpdir(), "banco-vivo-bootstrap-"));
  try {
    const source = join(scratch, "combined.sqlite");
    const bank = new Bank(source);
    try { seedBank(bank, { ...seed, openWeaknesses: false }); }
    finally { bank.close(); }
    execFileSync(process.execPath, ["--disable-warning=ExperimentalWarning",
      EXPORT_SCRIPT, source, bankPath, ecosystemPath],
    { encoding: "utf8", maxBuffer: 16 * 1024 * 1024, timeout: 600_000 });
  } finally { rmSync(scratch, { recursive: true, force: true }); }
}
