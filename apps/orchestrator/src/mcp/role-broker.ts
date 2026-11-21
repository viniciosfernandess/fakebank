import { randomUUID } from "node:crypto";
import { chmodSync, unlinkSync } from "node:fs";
import { createServer, type Server, type Socket } from "node:net";
import { join } from "node:path";
import type { EventStore } from "../../../../packages/event-store/src/index.ts";
import type { AgentSpec, AgentTool } from "../agent-loop.ts";

interface Session {
  agentId: string;
  runId: string;
  role: AgentSpec<unknown>["role"];
  token: string;
  tools: Map<string, AgentTool>;
  signal: AbortSignal;
  maxCalls: number;
  calls: number;
  socket?: Socket;
}

type Request = { type: "hello"; agentId: string; token: string } |
  { type: "call"; id: string; tool: string; input: unknown };

export class RoleToolBroker {
  readonly socketPath: string;
  private readonly events: EventStore;
  private readonly server: Server;
  private readonly sessions = new Map<string, Session>();
  private started = false;
  private starting: Promise<void> | undefined;
  constructor(dataDir: string, events: EventStore) {
    this.events = events;
    this.socketPath = join(dataDir, `bv-mcp-${randomUUID().slice(0, 8)}.sock`);
    this.server = createServer((socket) => this.accept(socket));
    events.db.exec(`CREATE TABLE IF NOT EXISTS role_tool_calls (
      run_id TEXT NOT NULL, agent_id TEXT NOT NULL, call_id TEXT NOT NULL,
      tool TEXT NOT NULL, kind TEXT NOT NULL,
      status TEXT NOT NULL CHECK(status IN ('started','completed','failed')),
      started_at TEXT NOT NULL, finished_at TEXT,
      PRIMARY KEY(run_id,agent_id,call_id)
    );
    CREATE INDEX IF NOT EXISTS role_tool_calls_pending
      ON role_tool_calls(run_id,agent_id,status);`);
  }
  hasUncertainCall(runId: string, agentId: string): boolean {
    return Boolean(this.events.db.prepare(`SELECT 1 FROM role_tool_calls
      WHERE run_id=? AND agent_id=? AND status='started' LIMIT 1`).get(runId, agentId));
  }
  hasNonReadCall(runId: string, agentId: string): boolean {
    return Boolean(this.events.db.prepare(`SELECT 1 FROM role_tool_calls
      WHERE run_id=? AND agent_id=? AND kind!='investigate'
        AND NOT (kind='code' AND tool IN ('repo.read','repo.search','repo.diff'))
      LIMIT 1`).get(runId, agentId));
  }
  async start(): Promise<void> {
    if (this.started) return;
    if (this.starting) return this.starting;
    this.starting = new Promise<void>((resolve, reject) => {
      this.server.once("error", reject);
      this.server.listen(this.socketPath, () => {
        this.server.off("error", reject);
        chmodSync(this.socketPath, 0o600);
        this.started = true;
        resolve();
      });
    });
    try { await this.starting; }
    finally { this.starting = undefined; }
  }
  register<T>(spec: AgentSpec<T>, signal: AbortSignal): string {
    if (!this.started) throw new Error("ROLE_BROKER_NOT_STARTED");
    const maxCalls = spec.maxToolCalls ?? 20;
    if (!Number.isSafeInteger(maxCalls) || maxCalls < 0 || maxCalls > 100)
      throw new Error("AGENT_INVALID_TOOL_LIMIT");
    const token = randomUUID();
    const prior = this.events.db.prepare(`SELECT COUNT(*) n FROM events
      WHERE round_id=? AND actor_id=? AND type='tool.called'`)
      .get(spec.runId, spec.agentId) as { n: number };
    const journaled = this.events.db.prepare(`SELECT COUNT(*) n FROM role_tool_calls
      WHERE run_id=? AND agent_id=?`).get(spec.runId, spec.agentId) as { n: number };
    const session: Session = { agentId: spec.agentId, runId: spec.runId, role: spec.role,
      token, tools: new Map(spec.tools.map((tool) => [tool.name, tool])), signal,
      maxCalls, calls: Math.max(prior.n, journaled.n) };
    this.sessions.set(token, session);
    return token;
  }
  revoke(token: string): void {
    const session = this.sessions.get(token);
    session?.socket?.destroy();
    this.sessions.delete(token);
  }
  async close(): Promise<void> {
    for (const token of this.sessions.keys()) this.revoke(token);
    if (!this.started) return;
    await new Promise<void>((resolve) => this.server.close(() => resolve()));
    try { unlinkSync(this.socketPath); } catch { /* Node removes Unix sockets on close on some platforms. */ }
    this.started = false;
  }
  private accept(socket: Socket): void {
    let session: Session | undefined;
    let buffer = "";
    socket.setEncoding("utf8");
    socket.on("data", (chunk: string) => {
      buffer += chunk;
      if (buffer.length > 1_000_000) { socket.destroy(); return; }
      let newline = buffer.indexOf("\n");
      while (newline >= 0) {
        const line = buffer.slice(0, newline);
        buffer = buffer.slice(newline + 1);
        let request: Request;
        try { request = JSON.parse(line) as Request; }
        catch { socket.destroy(); return; }
        if (!session) {
          if (request.type !== "hello") { socket.destroy(); return; }
          const candidate = this.sessions.get(request.token);
          if (!candidate || candidate.agentId !== request.agentId ||
            candidate.socket && !candidate.socket.destroyed) {
            socket.destroy(); return;
          }
          session = candidate;
          candidate.socket = socket;
          socket.write('{"type":"ready"}\n');
        } else if (request.type === "call") {
          void this.handleCall(session, request, socket);
        } else socket.destroy();
        newline = buffer.indexOf("\n");
      }
    });
    socket.on("close", () => { if (session?.socket === socket) delete session.socket; });
  }
  private async handleCall(session: Session, request: Extract<Request, { type: "call" }>, socket: Socket): Promise<void> {
    const tool = session.tools.get(request.tool);
    const parsed = tool?.schema.safeParse(request.input);
    session.calls++;
    const allowed = tool && parsed?.success && session.calls <= session.maxCalls &&
      !session.signal.aborted && /^[a-f0-9-]{36}$/.test(request.id);
    let ok = false;
    let content = "Tool unavailable";
    if (allowed) {
      let registered = false;
      try {
        this.events.db.prepare(`INSERT INTO role_tool_calls
          (run_id,agent_id,call_id,tool,kind,status,started_at)
          VALUES (?,?,?,?,?,'started',?)`).run(session.runId, session.agentId,
            request.id, request.tool, tool.kind, new Date().toISOString());
        registered = true;
      } catch { /* A repeated call ID cannot execute a tool twice. */ }
      if (registered) {
        const controller = new AbortController();
        const onAbort = () => controller.abort(session.signal.reason);
        session.signal.addEventListener("abort", onAbort, { once: true });
        const timeout = setTimeout(() => controller.abort(new Error("tool_timeout")),
          tool.timeoutMs?.(parsed.data) ?? 10_000);
        let rejectAborted: ((reason: unknown) => void) | undefined;
        const aborted = new Promise<never>((_, reject) => { rejectAborted = reject; });
        const onToolAbort = () => rejectAborted?.(controller.signal.reason);
        controller.signal.addEventListener("abort", onToolAbort, { once: true });
        const executed = Promise.resolve().then(() => tool.execute(parsed.data, controller.signal));
        const tracked = executed.then((value) => {
          this.finishCall(session, request.id, "completed");
          return value;
        }, (error: unknown) => {
          this.finishCall(session, request.id, "failed");
          throw error;
        });
        try {
          const value = await Promise.race([tracked, aborted]);
          content = JSON.stringify(value) ?? "null";
          ok = true;
        } catch (error) {
          const message = error instanceof Error ? error.message : "";
          content = /^(?:PATCH|DEF_CODE)_[A-Z0-9_]+$/.test(message) ?
            message : "Tool failed";
        }
        finally {
          clearTimeout(timeout);
          session.signal.removeEventListener("abort", onAbort);
          controller.signal.removeEventListener("abort", onToolAbort);
        }
      }
    }
    this.events.append({ round_id: session.runId, ts: new Date().toISOString(), type: "tool.called",
      actor: { id: session.agentId, role: session.role }, public_summary_pt: `${request.tool}: ${ok ? "ok" : "erro"}`,
      public: { tool: request.tool, ok, kind: tool?.kind ?? "investigate" } });
    if (!socket.destroyed) socket.write(JSON.stringify({ type: "result", id: request.id,
      ok, content: content.slice(0, 8000) }) + "\n");
  }
  private finishCall(session: Session, id: string, status: "completed" | "failed"): void {
    this.events.db.prepare(`UPDATE role_tool_calls SET status=?,finished_at=?
      WHERE run_id=? AND agent_id=? AND call_id=? AND status='started'`)
      .run(status, new Date().toISOString(), session.runId, session.agentId, id);
  }
}
