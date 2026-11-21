import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { exportBankSnapshot } from "./export-ecosystem-snapshot.mjs";

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  if (process.argv.length !== 4) {
    process.stderr.write("Usage: node scripts/export-bank-snapshot.mjs <combined-bank.sqlite> <new-bank.sqlite>\n");
    process.exitCode = 2;
  } else {
    try {
      process.stdout.write(JSON.stringify(exportBankSnapshot(process.argv[2], process.argv[3])) + "\n");
    } catch (error) {
      process.stderr.write(`${error.message}\n`);
      process.exitCode = 1;
    }
  }
}
