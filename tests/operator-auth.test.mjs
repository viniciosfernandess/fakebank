import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Bank } from "../apps/world/src/bank.ts";
import { OperatorAuth } from "../apps/world/src/operator-auth.ts";

test("local operators have durable credentials, roles, lockout and immutable login history", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-operator-auth-"));
  const bank = new Bank(join(dir, "bank.sqlite"));
  let now = new Date("2026-11-14T12:00:00.000Z");
  try {
    const auth = new OperatorAuth(bank, () => now);
    assert.throws(() => auth.bootstrap("a", "valid-password-123"), /OPERATOR_INPUT_INVALID/);
    assert.throws(() => auth.bootstrap("admin_one", "short"), /OPERATOR_INPUT_INVALID/);
    assert.deepEqual(auth.bootstrap("admin_one", "valid-password-123"),
      { id: "admin_one", role: "admin" });
    assert.throws(() => auth.bootstrap("admin_two", "valid-password-123"),
      /OPERATOR_ALREADY_BOOTSTRAPPED/);
    assert.deepEqual(auth.add("admin_one", "checker_two", "reviewer", "checker-password-123"),
      { id: "checker_two", role: "reviewer" });
    assert.throws(() => auth.add("checker_two", "maker_three", "maker", "maker-password-123"),
      /OPERATOR_FORBIDDEN/);
    assert.throws(() => auth.require(auth.authenticate("checker_two", "checker-password-123"),
      ["maker"]), /OPERATOR_FORBIDDEN/);
    for (let index = 0; index < 5; index++)
      assert.throws(() => auth.authenticate("checker_two", "incorrect-password"),
        /OPERATOR_BAD_CREDENTIALS/);
    assert.throws(() => auth.authenticate("checker_two", "checker-password-123"),
      /OPERATOR_BAD_CREDENTIALS/);
    now = new Date(now.getTime() + 16 * 60_000);
    assert.deepEqual(auth.authenticate("checker_two", "checker-password-123"),
      { id: "checker_two", role: "reviewer" });
    auth.changePassword("checker_two", "checker-password-123", "new-checker-password-123");
    assert.throws(() => auth.authenticate("checker_two", "checker-password-123"),
      /OPERATOR_BAD_CREDENTIALS/);
    assert.deepEqual(auth.authenticate("checker_two", "new-checker-password-123"),
      { id: "checker_two", role: "reviewer" });
    assert.throws(() => auth.disable("checker_two", "admin_one"), /OPERATOR_FORBIDDEN/);
    assert.throws(() => auth.disable("admin_one", "admin_one"), /OPERATOR_LAST_ADMIN/);
    auth.disable("admin_one", "checker_two");
    assert.throws(() => auth.authenticate("checker_two", "new-checker-password-123"),
      /OPERATOR_BAD_CREDENTIALS/);
    const stored = bank.db.prepare("SELECT password_hash,salt FROM operator_accounts WHERE id=?")
      .get("checker_two");
    assert.equal(stored.password_hash.includes("checker-password-123"), false);
    assert.equal(stored.salt.includes("checker-password-123"), false);
    assert.throws(() => bank.db.prepare("DELETE FROM operator_auth_events").run(),
      /OPERATOR_AUTH_HISTORY_IMMUTABLE/);
    assert.deepEqual(bank.db.prepare("SELECT action FROM operator_admin_events ORDER BY id")
      .all().map((row) => row.action),
      ["bootstrap", "enroll", "password_changed", "disabled"]);
    assert.throws(() => bank.db.prepare("DELETE FROM operator_admin_events").run(),
      /OPERATOR_ADMIN_HISTORY_IMMUTABLE/);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});
