import { lstatSync } from "node:fs";
import { verifySplitSnapshots } from "../../../scripts/verify-split-snapshot.mjs";

const [bankPath, ecosystemPath] = process.argv.slice(2);
if (!bankPath || !ecosystemPath || !process.send)
  throw new Error("CROSS_BOOK_VERIFIER_STARTUP_INVALID");
for (const path of [bankPath, ecosystemPath]) {
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0)
    throw new Error("CROSS_BOOK_VERIFIER_FILE_NOT_PRIVATE");
}
// Keep verification available while the server drains after terminal Ctrl+C.
process.on("SIGINT", () => {});
process.once("disconnect", () => process.exit(0));
process.send({ version: 1, ready: true, pid: process.pid });
process.on("message", (raw) => {
  if (!raw || typeof raw !== "object" || Array.isArray(raw) ||
    raw.version !== 1 || !Number.isSafeInteger(raw.id) || raw.operation !== "verify" ||
    Object.keys(raw).some((key) => !["version", "id", "operation"].includes(key))) return;
  try {
    const value = verifySplitSnapshots(bankPath, ecosystemPath);
    process.send({ version: 1, id: raw.id, ok: true, value });
  } catch (error) {
    process.send({ version: 1, id: raw.id, ok: false,
      code: error instanceof Error ? error.message : "CROSS_BOOK_VERIFIER_FAILED" });
  }
});
