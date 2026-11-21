import { createHash } from "node:crypto";

interface SpiLatencyBase {
  min_ms: number;
  p50_ms: number;
  p99_ms: number;
  max_ms: number;
}
export type SpiLatencyPolicy = (SpiLatencyBase & { version: 1 }) |
  (SpiLatencyBase & { version: 2 | 3; timeout_ms: number });

export function parseSpiLatencyPolicy(bytes: Uint8Array): SpiLatencyPolicy {
  if (bytes.byteLength === 0 || bytes.byteLength > 4_096) throw new Error("SPI_LATENCY_POLICY_INVALID");
  let value: unknown;
  try { value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); }
  catch { throw new Error("SPI_LATENCY_POLICY_INVALID"); }
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new Error("SPI_LATENCY_POLICY_INVALID");
  const policy = value as Partial<SpiLatencyBase> & { version?: unknown; timeout_ms?: unknown };
  const keys = ["version", "min_ms", "p50_ms", "p99_ms", "max_ms",
    ...(policy.version === 2 || policy.version === 3 ? ["timeout_ms"] : [])];
  const validMs = (ms: unknown): ms is number =>
    Number.isSafeInteger(ms) && (ms as number) >= 0 && (ms as number) <= 60_000;
  if (Object.keys(policy).length !== keys.length ||
    Object.keys(policy).some((key) => !keys.includes(key)) ||
    (policy.version !== 1 && policy.version !== 2 && policy.version !== 3) ||
    !validMs(policy.min_ms) || !validMs(policy.p50_ms) ||
    !validMs(policy.p99_ms) || !validMs(policy.max_ms) ||
    policy.min_ms > policy.p50_ms || policy.p50_ms > policy.p99_ms ||
    policy.p99_ms > policy.max_ms ||
    (policy.version !== 1 && (!validMs(policy.timeout_ms) ||
      policy.timeout_ms <= policy.max_ms)))
    throw new Error("SPI_LATENCY_POLICY_INVALID");
  return policy as SpiLatencyPolicy;
}

export function spiLatencyMs(endToEndId: string, policy: SpiLatencyPolicy): number {
  const digest = createHash("sha256").update(endToEndId).digest();
  const quantile = digest.readUInt32BE(0) / 0x1_0000_0000;
  if (quantile <= 0.5)
    return Math.round(policy.min_ms + (policy.p50_ms - policy.min_ms) * quantile / 0.5);
  if (quantile <= 0.99)
    return Math.round(policy.p50_ms + (policy.p99_ms - policy.p50_ms) * (quantile - 0.5) / 0.49);
  return Math.round(policy.p99_ms + (policy.max_ms - policy.p99_ms) * (quantile - 0.99) / 0.01);
}
