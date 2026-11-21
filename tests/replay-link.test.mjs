import { test } from "node:test";
import assert from "node:assert/strict";
import { parseMomentPosition, resolveMomentCursor } from "../packages/replay-link/src/index.ts";

test("time and named chapter links resolve to a public event cursor", () => {
  const events = ["round.started", "attack.succeeded", "sentinel.alert",
    "attack.succeeded", "deploy.succeeded"].map((type, index) =>
    ({ type, ts: new Date(Date.UTC(2026, 10, 12, 12, 0, index)).toISOString() }));
  assert.equal(resolveMomentCursor(events, parseMomentPosition(undefined)), 5);
  assert.equal(resolveMomentCursor(events, parseMomentPosition("2")), 3);
  assert.equal(resolveMomentCursor(events, parseMomentPosition("chapter:breach-2")), 4);
  assert.equal(resolveMomentCursor(events, parseMomentPosition("chapter:seal-1")), 5);
  assert.equal(resolveMomentCursor(events, parseMomentPosition("chapter:restore-1")), null);
  for (const invalid of ["chapter:breach-0", "chapter:unknown-1", "86401", "-1", "1.5"])
    assert.equal(parseMomentPosition(invalid), null);
});
