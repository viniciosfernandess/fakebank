import { fork, type ChildProcess } from "node:child_process";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";

export interface CrossBookReport {
  ok: boolean;
  bank_pi_cents: number | null;
  spi_pi_cents: number | null;
  pending_spi_cents: number;
  pending_pix: number;
  pending_inbound: number;
  pending_med: number;
  pending_returns: number;
  pending_cautelar_returns: number;
  bank_schema_drift: number;
  ecosystem_schema_drift: number;
  ledger_drift: number;
  psp_account_drift: number;
  root_overflow: number;
  transfer_drift: number;
  spi_message_drift: number;
  command_drift: number;
  return_command_drift: number;
  cautelar_return_drift: number;
  med_hold_drift: number;
  med_command_drift: number;
}

const REPORT_COUNTS = ["pending_spi_cents", "pending_pix", "pending_inbound", "pending_med",
  "pending_returns", "pending_cautelar_returns", "bank_schema_drift",
  "ecosystem_schema_drift", "ledger_drift", "psp_account_drift",
  "root_overflow", "transfer_drift", "spi_message_drift", "command_drift",
  "return_command_drift", "cautelar_return_drift", "med_hold_drift",
  "med_command_drift"] as const;

function isCrossBookReport(value: unknown): value is CrossBookReport {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const report = value as Partial<CrossBookReport>;
  return typeof report.ok === "boolean" &&
    [report.bank_pi_cents, report.spi_pi_cents].every((amount) =>
      amount === null || Number.isSafeInteger(amount) && (amount as number) >= 0) &&
    REPORT_COUNTS.every((key) => Number.isSafeInteger(report[key]) &&
      (report[key] as number) >= 0);
}

export class CrossBookVerifierClient {
  private readonly child: ChildProcess;
  private readonly pending = new Map<number, { resolve: (value: CrossBookReport) => void;
    reject: (error: Error) => void; timer: NodeJS.Timeout }>();
  private nextId = 1;
  private stopped = false;
  readonly processId: number;

  private constructor(child: ChildProcess, processId: number) {
    this.child = child;
    this.processId = processId;
    child.on("message", (raw: unknown) => {
      if (!raw || typeof raw !== "object" || Array.isArray(raw)) return;
      const reply = raw as { version?: unknown; id?: unknown; ok?: unknown;
        value?: unknown; code?: unknown };
      if (reply.version !== 1 || !Number.isSafeInteger(reply.id)) return;
      const pending = this.pending.get(reply.id as number);
      if (!pending) return;
      this.pending.delete(reply.id as number);
      clearTimeout(pending.timer);
      if (reply.ok === true && isCrossBookReport(reply.value))
        pending.resolve(reply.value);
      else if (reply.ok === true)
        pending.reject(new Error("CROSS_BOOK_VERIFIER_REPLY_INVALID"));
      else pending.reject(new Error(typeof reply.code === "string" ? reply.code :
        "CROSS_BOOK_VERIFIER_FAILED"));
    });
    const fail = () => {
      this.stopped = true;
      for (const pending of this.pending.values()) {
        clearTimeout(pending.timer);
        pending.reject(new Error("CROSS_BOOK_VERIFIER_EXITED"));
      }
      this.pending.clear();
    };
    child.on("exit", fail);
    child.on("error", fail);
  }

  static async start(bankPath: string, ecosystemPath: string): Promise<CrossBookVerifierClient> {
    if (!existsSync(bankPath) || !existsSync(ecosystemPath))
      throw new Error("CROSS_BOOK_VERIFIER_FILE_MISSING");
    const worker = fileURLToPath(new URL("./verifier-worker.mjs", import.meta.url));
    const child = fork(worker, [bankPath, ecosystemPath], {
      execArgv: ["--disable-warning=ExperimentalWarning"],
      env: { PATH: process.env.PATH ?? "" },
      stdio: ["ignore", "ignore", "ignore", "ipc"],
    });
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        child.kill();
        reject(new Error("CROSS_BOOK_VERIFIER_STARTUP_TIMEOUT"));
      }, 5_000);
      const fail = () => {
        clearTimeout(timer);
        reject(new Error("CROSS_BOOK_VERIFIER_STARTUP_FAILED"));
      };
      child.once("exit", fail);
      child.once("error", fail);
      child.on("message", (raw: unknown) => {
        if (!raw || typeof raw !== "object" || Array.isArray(raw)) return;
        const ready = raw as { version?: unknown; ready?: unknown; pid?: unknown };
        if (ready.version !== 1 || ready.ready !== true ||
          !Number.isSafeInteger(ready.pid)) return;
        clearTimeout(timer);
        child.off("exit", fail);
        child.off("error", fail);
        resolve(new CrossBookVerifierClient(child, ready.pid as number));
      });
    });
  }

  verify(): Promise<CrossBookReport> {
    if (this.stopped || !this.child.connected)
      return Promise.reject(new Error("CROSS_BOOK_VERIFIER_EXITED"));
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        if (this.pending.delete(id)) reject(new Error("CROSS_BOOK_VERIFIER_TIMEOUT"));
      }, 30_000);
      this.pending.set(id, { resolve, reject, timer });
      this.child.send({ version: 1, id, operation: "verify" }, (error) => {
        if (error && this.pending.delete(id)) {
          clearTimeout(timer);
          reject(error);
        }
      });
    });
  }

  async close(): Promise<void> {
    if (this.stopped) return;
    this.stopped = true;
    await new Promise<void>((resolve) => {
      this.child.once("exit", () => resolve());
      this.child.kill();
    });
  }
}
