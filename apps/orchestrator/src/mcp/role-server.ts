import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { createConnection } from "node:net";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

function argument(name: string): string {
  const index = process.argv.indexOf(name);
  const value = process.argv[index + 1];
  if (index < 0 || !value) throw new Error(`Missing ${name}`);
  return value;
}
const socketPath = argument("--socket");
const agentId = argument("--agent");
const token = argument("--token");
const manifestPath = argument("--manifest");
const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as {
  tools: { name: string; description: string; inputSchema: Record<string, unknown> }[] };
if (!Array.isArray(manifest.tools) || manifest.tools.some((tool) =>
  typeof tool.name !== "string" || typeof tool.description !== "string" ||
  !tool.inputSchema || typeof tool.inputSchema !== "object"))
  throw new Error("ROLE_MANIFEST_INVALID");

const socket = createConnection(socketPath);
socket.setEncoding("utf8");
let buffer = "";
let readyResolve: (() => void) | undefined;
let readyReject: ((error: Error) => void) | undefined;
const ready = new Promise<void>((resolve, reject) => { readyResolve = resolve; readyReject = reject; });
const pending = new Map<string, { resolve: (value: { ok: boolean; content: string }) => void;
  reject: (error: Error) => void }>();
socket.on("connect", () => socket.write(JSON.stringify({ type: "hello", agentId, token }) + "\n"));
socket.on("data", (chunk: string) => {
  buffer += chunk;
  if (buffer.length > 1_000_000) { socket.destroy(); return; }
  let newline = buffer.indexOf("\n");
  while (newline >= 0) {
    const line = buffer.slice(0, newline);
    buffer = buffer.slice(newline + 1);
    const message = JSON.parse(line) as { type: string; id?: string; ok?: boolean; content?: string };
    if (message.type === "ready") readyResolve?.();
    if (message.type === "result" && message.id) {
      const waiter = pending.get(message.id);
      if (waiter) {
        pending.delete(message.id);
        waiter.resolve({ ok: message.ok === true, content: message.content ?? "" });
      }
    }
    newline = buffer.indexOf("\n");
  }
});
function connectionFailed(): void {
  const error = new Error("ROLE_BROKER_DISCONNECTED");
  readyReject?.(error);
  for (const waiter of pending.values()) waiter.reject(error);
  pending.clear();
}
socket.on("error", connectionFailed);
socket.on("close", connectionFailed);
await Promise.race([ready, new Promise<never>((_, reject) =>
  setTimeout(() => reject(new Error("ROLE_BROKER_TIMEOUT")), 5_000))]);

const server = new Server({ name: "banco-vivo-role", version: "1.0.0" },
  { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: manifest.tools }));
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const name = request.params.name;
  if (!manifest.tools.some((tool) => tool.name === name))
    return { content: [{ type: "text", text: "Tool unavailable" }], isError: true };
  const id = randomUUID();
  const response = new Promise<{ ok: boolean; content: string }>((resolve, reject) =>
    pending.set(id, { resolve, reject }));
  socket.write(JSON.stringify({ type: "call", id, tool: name,
    input: request.params.arguments ?? {} }) + "\n");
  try {
    const result = await response;
    return { content: [{ type: "text", text: result.content }], isError: !result.ok };
  } catch {
    return { content: [{ type: "text", text: "Tool unavailable" }], isError: true };
  }
});
await server.connect(new StdioServerTransport());
