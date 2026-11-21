import { gzipSync, gunzipSync } from "node:zlib";
import type { WorldState } from "./index.ts";

export function encodeKeyframe(state: WorldState): Uint8Array { return gzipSync(JSON.stringify(state)); }
export function decodeKeyframe(data: Uint8Array): WorldState { return JSON.parse(gunzipSync(data).toString("utf8")) as WorldState; }
