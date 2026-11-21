# PSP notice inbox (synthetic)

The PSP notice inbox delivers existing cautelar and MED notices to an explicitly
provisioned synthetic PSP account holder. It runs only through the local
loopback gateway at `/api/client/psp/notices`. The operator must verify the
synthetic identity/account relationship before provisioning; the service never
infers ownership from holder names or Pix keys.

## Provision and recovery

Open `/psp` on the local Banco Vivo UI and enter the intended identity ID.
The browser generates an Ed25519 key pair and stores the non-exportable private
key in its IndexedDB. Copy only the displayed public key (base64url SPKI DER)
to a local file. **Never put a private key in this repository, a CLI argument,
or an operator file.** An authenticated admin provisions the explicit mapping:

```text
pnpm operator psp-notice-provision <identity-id> <psp-account-id> <public-key-file> <admin-id>
```

The CLI prompts for the admin password without echoing it. The account must be
active; an account, identity ID, or public key already assigned to another
identity is rejected. To replace a lost key, the admin first revokes the
identity and then reprovisions it with a *different* public key:

```text
pnpm operator psp-notice-revoke <identity-id> <admin-id>
pnpm operator psp-notice-reprovision <identity-id> <new-public-key-file> <admin-id>
```

Revocation ends existing sessions and cursors. Reprovisioning records an
immutable administrative event. The new client proves possession of its key
when logging in. The CLI receives public keys only.
Freezing the PSP account suspends login, existing sessions, and reprovisioning
until the account becomes active again.
Clearing the browser's site data loses its non-exportable private key. Recover
by revoking the identity, generating a new browser key, and reprovisioning the
new public key. The browser keeps the short-lived session token only in memory.

## Recipient portal

After the operator provisions the public key, the account holder uses `/psp`
to sign in, refresh notices, page through older cautelar/MED notices, and sign
out. Each request uses the existing one-use signed challenge protocol below;
the portal never asks for or displays the private key. The portal is hidden in
presentation mode and only available while the local bank is active.

## Client protocol

All examples below use placeholder values and no real key material. Send POST
requests from loopback with the same origin as the local server.

1. Generate a fresh 24-byte random `client_nonce` encoded as base64url. Sign
   `BancoVivo:psp-notice:begin-login:v1:<identity_id>:<client_nonce>` using the
   local Ed25519 private key. POST `/api/client/psp/notices/login-challenge`
   with `identity_id`, `client_nonce`, and the base64url `signature`. A repeated
   nonce is rejected. Only a valid signed request consumes the holder's
   challenge quota. Sign the returned `message` with the same private key.
2. POST `/api/client/psp/notices/login` with `identity_id`, `challenge_id`,
   and the base64url signature. The one-use challenge yields a 15-minute session
   token; only its SHA-256 hash is stored.
3. POST `/api/client/psp/notices/operation-challenge` with
   `Authorization: Bearer <session-token>` and
   `{ "method": "GET", "limit": 20 }`. Sign the returned `message`.
4. GET `/api/client/psp/notices?limit=20` with the same bearer token plus
   `X-PSP-Challenge` and `X-PSP-Signature`. A bearer token alone cannot read
   notices. To continue, repeat step 3 with the returned opaque `next_cursor`
   and then include that cursor in the GET query. Each operation proof and
   cursor is single use and bound to the session and account.
5. To log out, request a POST operation challenge and send a signed POST to
   `/api/client/psp/notices/logout`.

Login and operation challenges expire after two real minutes; cursors expire
after 15 real minutes. Reads use a stable order across cautelar and MED notices,
and responses omit global notice, hold, case, transfer, account, and identity
IDs. The API and loopback proxy send `Cache-Control: no-store`.

The browser portal polls the signed inbox every 15 seconds while its page and
session remain open. The holder may explicitly enable browser system notices;
only notices arriving after the first successful poll trigger a generic title
and body, without account, amount, case, or message content. Browser permission
is requested only after a click. This does not deliver push notifications after
the page closes; the authenticated inbox remains the source of truth. In the
default separated runtime, PSP balances,
notice access identities, and signed challenges live in the ecosystem worker
and its SQLite file; the bank reaches them through the versioned client IPC.
