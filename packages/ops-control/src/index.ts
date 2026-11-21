import { readFileSync, writeFileSync, renameSync, existsSync, rmSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { join } from "node:path";
import { z } from "zod";

const stateSchema = z.strictObject({
  level: z.union([z.literal(0), z.literal(1), z.literal(2), z.literal(3)]),
  hiddenSeqs: z.array(z.number().int().positive()).max(100),
  hiddenRoundIds: z.array(z.string().regex(/^r\d{2}$/)).max(14),
});
export type OpsState = z.infer<typeof stateSchema>;
const DEFAULT: OpsState = { level: 0, hiddenSeqs: [], hiddenRoundIds: [] };

export class OpsControl {
  readonly path: string;
  private readonly now: () => number;
  private lastRead = -Infinity;
  private state: OpsState = DEFAULT;
  constructor(dataDir: string, now: () => number = () => Date.now()) {
    this.path = join(dataDir, "ops.json");
    this.now = now;
  }
  read(): OpsState {
    if (this.now() - this.lastRead < 10_000) return this.state;
    this.lastRead = this.now();
    if (!existsSync(this.path)) { this.state = DEFAULT; return this.state; }
    try { this.state = stateSchema.parse(JSON.parse(readFileSync(this.path, "utf8"))); }
    catch { this.state = { level: 3, hiddenSeqs: [], hiddenRoundIds: [] }; }
    return this.state;
  }
  readFresh(): OpsState {
    this.lastRead = -Infinity;
    return this.read();
  }
  write(next: OpsState): void {
    const state = stateSchema.parse(next);
    const staging = `${this.path}.tmp-${randomUUID()}`;
    try {
      writeFileSync(staging, JSON.stringify(state, null, 2), { mode: 0o600, flag: "wx" });
      renameSync(staging, this.path);
    } finally { rmSync(staging, { force: true }); }
    this.state = state;
    this.lastRead = this.now();
  }
}
