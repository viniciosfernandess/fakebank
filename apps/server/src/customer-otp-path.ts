import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

export function customerOtpMailboxDirectory(dataDir: string): string {
  const absolute = resolve(dataDir);
  const local = join(absolute, ".customer-otp");
  if (Buffer.byteLength(join(local, "mailbox.sock"), "utf8") <= 100) return local;
  const suffix = createHash("sha256").update(absolute).digest("hex").slice(0, 20);
  return join(tmpdir(), `bvotp-${process.getuid?.() ?? "user"}-${suffix}`);
}
