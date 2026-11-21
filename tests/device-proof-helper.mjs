import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";

export async function bindDeviceKey(app, headers) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const challenge = await app.inject({ method: "POST",
    url: "/devices/current/key/challenge", headers });
  assert.equal(challenge.statusCode, 200);
  const { challenge_id, message } = challenge.json();
  const enrolled = await app.inject({ method: "POST", url: "/devices/current/key",
    headers, payload: { challenge_id,
      public_key: publicKey.export({ format: "der", type: "spki" }).toString("base64url"),
      signature: sign(null, Buffer.from(message), privateKey).toString("base64url") } });
  assert.equal(enrolled.statusCode, 200);
  assert.equal(enrolled.json().key_bound, true);
  return privateKey;
}

export async function signedOperationHeaders(app, headers, privateKey, path, body, method = "POST") {
  const challenge = await app.inject({ method: "POST",
    url: "/devices/current/operation-challenge", headers,
    payload: { method, path, ...(body === undefined ? {} : { body }) } });
  assert.equal(challenge.statusCode, 200);
  const { challenge_id, message } = challenge.json();
  return { ...headers, "x-device-challenge": challenge_id,
    "x-device-signature": sign(null, Buffer.from(message), privateKey).toString("base64url") };
}

export function signedRefresh(auth, refreshToken, privateKey) {
  const challenge = auth.beginRefresh(refreshToken);
  assert.equal(challenge.proof_required, true);
  return auth.refresh(refreshToken, { challengeId: challenge.challenge_id,
    signature: sign(null, Buffer.from(challenge.message), privateKey).toString("base64url") });
}
