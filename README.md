# FakeBank · Banco Vivo

FakeBank is a local banking simulator with a retail bank, a separate synthetic
payment ecosystem, and an Investment Banking desk. The project uses fictional
customers, counterparties, securities and money.

## Retail bank

Use Node.js 24.10 and pnpm 11.25. From the repository root:

```sh
pnpm install --frozen-lockfile
pnpm build
pnpm start:bank
```

Open [the customer portal](http://127.0.0.1:3000/cliente). The bank simulates
accounts, Pix and its settlement, cards, lending, onboarding, a double-entry
ledger, and operational monitoring. Startup creates local SQLite databases
under `data/`. The synthetic payment ecosystem runs separately from the
bank process. Neither the retail bank nor IB needs API credentials.
To seed the larger synthetic workload, start with an empty `DATA_DIR` and set
`FAKEBANK_SEED_PROFILE=full`.

The optional loopback fault laboratory uses a separate disposable data set.
Run `pnpm start:lab` after building and open
[the fault laboratory](http://127.0.0.1:3000/laboratorio).
To opt into agent-assisted code review, set `FAKEBANK_LOCAL_CODEX=1`
and use a locally authenticated Codex.
The public simulator keeps intentional vulnerability switches closed.

## Investment Banking

In a separate terminal:

```sh
pnpm start:ib
```

Open [the IB operations desk](http://127.0.0.1:3100).
**Rodar benchmark** compares reactive and predictive policies with the same
events and cutoffs. Use `node apps/ib/server.mjs --memory` for a disposable
session. See the [IB design](apps/ib/DESIGN.md) and
[decision agent design](apps/ib/INTELLIGENCE.md).

## Verify

```sh
pnpm test
node apps/ib/stress.mjs
```
