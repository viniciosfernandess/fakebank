# FakeBank

FakeBank is a local investment banking simulator for a synthetic debt issuance,
securities settlement, and intraday liquidity. It uses fictional counterparties
and money. No API key or external service is required.

## Run locally

With Node.js 24.10 or later:

```sh
node apps/ib/server.mjs
```

Open http://127.0.0.1:3100. Choose a scenario and advance the simulation
manually, or select **Executar até o fim** to run the selected policy.
**Rodar benchmark** compares reactive and predictive runs with identical
inputs, resources, and cutoffs.

SQLite stores the current day and its event history locally. Add `--memory`
to the startup command for a disposable session.

## Verify

```sh
node --test apps/ib/*.test.mjs
node apps/ib/stress.mjs
```

The [simulator design](apps/ib/DESIGN.md) describes the three desks and the
bookkeeping. The [intelligence design](apps/ib/INTELLIGENCE.md) documents the
isolated decision processes, execution controls, and reproducible stress tests.
