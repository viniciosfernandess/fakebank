import { chmodSync, lstatSync, mkdirSync, rmdirSync, unlinkSync } from "node:fs";
import { createConnection, createServer, type Server } from "node:net";
import { join } from "node:path";
import type { AuthEngine } from "../../world/src/auth.ts";
import { customerOtpMailboxDirectory } from "./customer-otp-path.ts";

const REQUEST_LIMIT = 256;

async function removeStaleSocket(path: string): Promise<void> {
  let entry: ReturnType<typeof lstatSync>;
  try { entry = lstatSync(path); }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw error;
  }
  if (!entry.isSocket() || entry.uid !== process.getuid?.())
    throw new Error("CUSTOMER_OTP_SOCKET_UNSAFE");
  const active = await new Promise<boolean>((resolve, reject) => {
    const socket = createConnection(path);
    socket.once("connect", () => { socket.destroy(); resolve(true); });
    socket.once("error", (error: NodeJS.ErrnoException) => {
      if (error.code === "ECONNREFUSED") resolve(false);
      else reject(error);
    });
  });
  if (active) throw new Error("CUSTOMER_OTP_SOCKET_IN_USE");
  unlinkSync(path);
}

export async function startCustomerOtpMailbox(auth: AuthEngine, dataDir: string):
  Promise<{ path: string; close(): Promise<void> }> {
  const directory = customerOtpMailboxDirectory(dataDir);
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const folder = lstatSync(directory);
  if (!folder.isDirectory() || folder.isSymbolicLink() ||
    folder.uid !== process.getuid?.()) throw new Error("CUSTOMER_OTP_DIRECTORY_UNSAFE");
  chmodSync(directory, 0o700);
  const path = join(directory, "mailbox.sock");
  await removeStaleSocket(path);
  const server: Server = createServer((socket) => {
    socket.setTimeout(3000, () => socket.destroy());
    let input = "";
    socket.on("data", (chunk: Buffer) => {
      if (socket.writableEnded) return;
      input += chunk.toString("utf8");
      if (Buffer.byteLength(input, "utf8") > REQUEST_LIMIT) { socket.end("NOT_FOUND\n"); return; }
      if (!input.includes("\n")) return;
      const line = input.slice(0, input.indexOf("\n"));
      input = "";
      let otp: string | undefined;
      try {
        const request: unknown = JSON.parse(line);
        if (request && typeof request === "object" && !Array.isArray(request)) {
          const { cpf, challenge_id: challengeId } = request as Record<string, unknown>;
          if (typeof cpf === "string" && /^\d{11}$/.test(cpf) &&
            typeof challengeId === "string" && /^[A-Za-z0-9_-]{1,128}$/.test(challengeId)) {
            const row = auth.bank.db.prepare(`SELECT c.customer_id FROM auth_challenges c
              JOIN customers u ON u.id=c.customer_id
              JOIN auth_devices d ON d.id=c.device_id
              WHERE c.id=? AND u.cpf=? AND c.used_at IS NULL AND c.expires_at>?
              AND d.fingerprint LIKE 'browser-%'`).get(challengeId, cpf,
                auth.bank.realNow().toISOString()) as { customer_id: string } | undefined;
            if (row) otp = auth.simulatedOtp(challengeId, row.customer_id);
          }
        }
      } catch { /* Invalid and expired challenges have the same result. */ }
      socket.end(otp ? `OTP ${otp}\n` : "NOT_FOUND\n");
    });
    socket.on("error", () => undefined);
  });
  try {
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(path, () => { server.off("error", reject); resolve(); });
    });
    chmodSync(path, 0o600);
  } catch (error) {
    const owned = server.listening;
    if (owned) await new Promise<void>((resolve) => server.close(() => resolve()));
    if (owned) try { unlinkSync(path); }
      catch (cleanupError) {
        if ((cleanupError as NodeJS.ErrnoException).code !== "ENOENT") throw cleanupError;
      }
    try { rmdirSync(directory); }
    catch (cleanupError) {
      if (!["ENOENT", "ENOTEMPTY"].includes((cleanupError as NodeJS.ErrnoException).code ?? ""))
        throw cleanupError;
    }
    throw error;
  }
  const entry = lstatSync(path);
  return { path, close: async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    try {
      const current = lstatSync(path);
      if (current.dev === entry.dev && current.ino === entry.ino) unlinkSync(path);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    try { rmdirSync(directory); }
    catch (error) {
      if (!["ENOENT", "ENOTEMPTY"].includes((error as NodeJS.ErrnoException).code ?? ""))
        throw error;
    }
  } };
}
