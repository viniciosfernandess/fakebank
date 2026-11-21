import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { exportSplitSnapshots } from "./export-ecosystem-snapshot.mjs";

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  if (process.argv.length !== 5) {
    process.stderr.write("Usage: node scripts/export-split-snapshot.mjs <combined-bank.sqlite> <new-bank.sqlite> <new-ecosystem.sqlite>\n");
    process.exitCode = 2;
  } else {
    try {
      process.stdout.write(JSON.stringify(exportSplitSnapshots(
        process.argv[2], process.argv[3], process.argv[4])) + "\n");
    } catch (error) {
      process.stderr.write(`${error.message}\n`);
      process.exitCode = 1;
    }
  }
}
