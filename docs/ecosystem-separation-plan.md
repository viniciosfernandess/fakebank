# Ecosystem trust-boundary cutover

Current-source update (2026-11-17): the default runtime now separates the
bank and ecosystem processes and SQLite files. The default
`rules/spi/latency.json` is now version 3, with an 80 ms configured median,
1,500 ms configured p99 and the same ten-second timeout. The version-2 figures
and shared-file description below are the earlier cutover baseline. Existing
queued commands retain their stored eligibility and deadline across the
policy upgrade.

This is the remaining Audit 2 F3/P0 cutover contract, not an implemented
trust boundary. Today `Bank`, `SpiNetwork`, and `PspNetwork` share `bank.sqlite`.
The customer API commits an `in_processing` Pix intent, reservation and outbox
command before a dispatcher submits the instruction. SPI retries are idempotent,
and a bank posting failure after SPI acceptance can be recovered after restart.
The queued command stores an immutable real-clock eligibility time calculated
from `rules/spi/latency.json` (version 2, 200 ms median, 2 s p99, and 10 s
response deadline). Restarting
with a different policy does not reschedule existing commands. The 50 ms
dispatcher interval adds scheduling jitter to the observed response time;
the p50/p99 values in the rule describe the configured command delay. New
queued commands also persist immutable real-clock queue and response timestamps;
version-2 commands persist an immutable real-clock deadline. After that
deadline, an SPI that has not accepted the command records `pacs.002 RJCT/AB03`
without moving PI funds. A previously recorded `ACSC` remains authoritative
even if the bank retries after the deadline. During SPI unavailability the bank
keeps the request visibly processing, then obtains the outcome when SPI returns.
Version-1 queued commands retain their original no-timeout contract after a
policy upgrade; old deadlines are never inferred from a new policy.
`Bank.pixLatencyMetrics()` reports observed response p50, p99 and maximum from
completed commands. Existing commands without both timestamps are excluded.
`pnpm verify:spi-latency-load` measures 1,000 queued payments on a real clock
and checks the bank, SPI and PSP books; the 24-hour synthetic day exercises a
different, accelerated workload and cannot validate wall-clock latency.
The direct bank, scheduled, and automatic paths still settle synchronously.
Queued Pix now commits a `pix_psp_inbound_outbox` command with the final bank
posting, then submits `PspNetwork.creditInbound` outside that bank transaction.
The command survives restart; a repeated delivery credits the PSP once.
The initial PSP fan-in review is idempotent across an acknowledgement failure.
An unacknowledged command makes PSP reconciliation fail and is visible to the
customer as pending recipient credit even after SPI settlement. Historical
version-1 Pix remains on the synchronous path. The dispatcher still invokes
the PSP object in the bank process, and both books still share `bank.sqlite`.
The bank posts its ledger entries and changes Pix status itself.
The receiving PSP's fan-in review now counts immutable sender facts paired with
its own inbound receipts; it no longer queries `pix_transfers` for the live
review. New pacs.008 messages carry `sender_account` and `root_transfer_id`,
which the PSP checks against the inbound delivery. SPI retries reject a changed
root ID, and bank/SPI reconciliation detects a changed recorded root. Legacy
messages without that field require an immutable PSP-owned inbound proof
imported from an accepted pending command before new PSP credit. The import
checks the bank Pix, outbox and SPI response once, records a local count/hash
seal, and fails startup if the imported proof set changes. Legacy receipts
acquire sender facts from the bank's historical Pix table during startup,
with a fail-closed consistency
check. The bank's queued PSP command carries immutable sender and settlement
time fields. The live PSP inbound path no longer reads bank Pix, but the
one-time historical migration and bank-owned cross-book reconciliation still
depend on bank tables. PSP path tracing
starts from its own immutable root fact for new or imported payments; it no
longer reads the bank Pix table. A legacy-path test changes the bank Pix
status and amount and confirms the PSP path remains unchanged while cross-book
reconciliation detects the drift. Runtime PSP reconciliation now checks its own
accounts, roots, holds and sender facts. Bank-owned `reconcilePsp()` compares
the MED projection, legacy roots, pending deliveries and receipts across the
two books; period close and sentinels use the combined result. After migration
markers are present, the PSP constructor uses only ecosystem tables; Bank
checks the cross-book history at startup. A test opens a migrated copy with
`pix_transfers`, `pix_returns`, `pix_psp_inbound_outbox` and `med_hops` removed,
then moves root funds within the PSP. The live Bank still shares its process
and writable SQLite file with the ecosystem, so this does not establish the
final trust boundary.
PSP root-cap reconciliation now uses immutable `psp_roots` facts for both new
receipts and imported legacy roots. The one-time import checks historical bank
Pix data, preserves existing fund balances, and migrates `psp_funds` to a PSP
root foreign key. Missing root facts fail startup after the migration marker;
cross-book checks still report mismatches against bank Pix and receipt data.
The earlier one-time root-fund import also retains its immutable marker and
rejects missing funds on later restarts.
The PSP now keeps its own MED hold record for availability checks, notices,
and hold-overflow reconciliation. A one-time import compares every historical
bank hop before marking migration complete; subsequent missing or changed
PSP holds fail startup and register cross-book drift. The bank still owns the
MED case and hop projection, and both records update inside the shared SQLite
transaction. This does not provide independent process or database ownership.
MED notices now reference the PSP hold instead of the bank's `med_hops` and
`med_cases` tables. Existing notice rows are checked against their hold and
copied in one SQLite transaction during schema cutover, preserving IDs and
immutable notice triggers. PSP transfers, cash-outs and cautelar now also
reference PSP roots; their old rows and linked cautelar notices migrate in one
transaction. No PSP schema table has a foreign key to bank Pix transfers. The
bank's `med_hops` table also no longer has a foreign key to PSP accounts:
existing hops migrate after the PSP imports and verifies its hold mirror.
Historical import and reconciliation still read bank tables, and all components
still share one process and SQLite file, so the database split remains open.
Returns and MED still call `spi.returnPayment` and the in-process PSP object
from `Bank`. Their PSP account and root debits now go through one PSP-owned
savepoint, so a failed account debit cannot leave the root funds decremented.
DICT fraud marking also goes through the PSP object; `Bank` no longer contains
direct `UPDATE psp_accounts` statements. This is an ownership cleanup, not a
trust boundary: `Bank` still holds the same SQLite connection and can write
another participant's accounts.

## Ownership after cutover

| State | Owner | Bank-visible interface |
| --- | --- | --- |
| Customer accounts, balance holds, bank ledger, Pix intents and risk decisions | Bank process and `bank.sqlite` | Bank API |
| PI balances, pacs.008/002/004 messages, availability, participant registry | SPI process and `ecosystem.sqlite` | Versioned `SpiClient` messages and acknowledgements |
| Ipê/Aroeira accounts, root funds, cautelar, MED hop balances and notices | PSP process(es) and `ecosystem.sqlite` | Idempotent participant commands and read models scoped to the recipient |
| External DICT directory and shared fraud markings | Ecosystem owner | Lookup and marking messages with explicit timestamps and completeness |

The final bank database must contain no writable `spi_participants`,
`spi_messages`, `psp_accounts`, or PSP root/cautelar/MED balance tables. An
integration test must prove that a bank connection cannot update a PSP account.
`Bank` must no longer issue direct `UPDATE psp_accounts` statements or call
the in-process `PspNetwork` for money movement.
The bank can retain its customer-owned `pix_keys` as an internal source of
truth, but publication to the DICT directory must be message-based.

## Snapshot export available before cutover

`pnpm export:ecosystem-snapshot <bank.sqlite> <new-ecosystem.sqlite>` creates a
new, private-mode SQLite file containing only `spi_`, `psp_`, and `dict_`
tables. The source is opened read-only under one consistent SQLite snapshot;
the exporter refuses an existing output and any ecosystem table with a foreign
key to a bank-owned table. It copies schema, data, indexes, and triggers, then
checks foreign keys, SQLite integrity, and a count/hash of each table against
the source snapshot. A populated external-Pix test opens the exported file
with `SpiNetwork` and `PspNetwork`, verifies the PI balance and PSP root, and
settles an inter-PSP root movement using only the exported database.

This is a migration artifact, not the live cutover. The running bank still
writes the original shared database, so an export made while writes continue
will become stale. Freeze writes, compare the final bank settlement projection
with the exported ecosystem, and switch to an authenticated process boundary
before using this file as the ecosystem source of truth. The export leaves the
source untouched and never deletes or overwrites an existing destination.

`pnpm export:bank-snapshot <combined-bank.sqlite> <new-bank.sqlite>` creates the
complementary bank-only file. `pnpm export:split-snapshot <combined-bank.sqlite>
<new-bank.sqlite> <new-ecosystem.sqlite>` creates both from one read-only source
transaction, so their table digests refer to the same database view. The bank
file contains no SPI, PSP or DICT tables; the ecosystem file contains no bank
tables. Each copy checks foreign keys, integrity, row counts and hashes. A
failure while creating the second copy removes the first generated output.
The populated export test proves that a connection to the bank-only file cannot
prepare a PSP account update, and the ecosystem-only connection cannot prepare
a bank account update. This still does not switch the running `Bank` to either
file: its constructor still instantiates both ecosystem objects on its bank
connection. See [split snapshot evidence](test-evidence/split-snapshot-2026-11-16.md).

The dual export now runs a read-only cross-file reconciliation before returning
the pair. It requires a drained Pix/SPI/PSP checkpoint and checks the bank PI
mirror, ledger balances, PSP accounts and roots, bank Pix versus SPI messages
and durable commands, inbound receipts and sender facts, and bank MED hops
versus PSP holds. A divergent pair is removed. A 400,000-history/1,000-external-
payment disposable load exported and reconciled both files in 122 seconds; see
[cutover reconciliation evidence](test-evidence/split-reconciliation-2026-11-16.md).
The verifier is for a frozen checkpoint. It cannot prove cross-process crash
recovery or consistency while the two owners accept new writes.

An initial `EcosystemClient`/worker contract can now open only the exported
ecosystem file in a child process. It exposes narrow versioned IPC operations
for account/DICT lookup, PI balance, idempotent SPI payment submission, PSP
inbound credit and PSP reconciliation. The worker rejects a combined database
and arbitrary SQL messages. A populated process test repeats a payment and
credit, restarts the child and confirms one movement on each ecosystem book.
The bank client sees only its own PI balance and routing/DICT fields; PSP
account balances and another participant's PI balance are not exposed.
The worker also answers a versioned recipient-evidence request with an external
account's existence, fraud flag and DICT fraud-history counters at a validated
simulated timestamp. `RiskEngine` now consumes recipient evidence through a
provider instead of querying PSP/DICT tables. A split-file test evaluates Pix
risk on the bank-only SQLite using evidence fetched from the child. The live
Bank provider still reads its in-process SPI object and the combined database;
the risk engine's read-side refactor does not switch production traffic.
The inbound PSP IPC command now wraps idempotent credit and fan-in cautelar
review in one ecosystem transaction. It returns only the hold ID and reason,
and supports a validated simulated processing timestamp. A five-sender
split-file fixture confirms one hold on the fifth receipt and the same result
after duplicate delivery and process restart. The bank dispatcher has not yet
been switched to this command.
The bank-owned due-command reader also works on a bank-only SQLite file. The
local dispatcher now delegates pacs.002 application to a bank transaction that
reloads the durable command, validates response identity and amount, and
applies or rejects it once. This is the bank-side consumption seam for the IPC
dispatcher; the existing runner still sends through its in-process SPI object.
The bank-only reader also exposes validated pending PSP credit commands. The
local dispatcher now delegates acknowledgement and its cautelar telemetry to
a bank transaction that reloads the command. An external coordinator can use
the same read/ack pair around the ecosystem worker's idempotent inbound
command; the live runner has not yet made that switch.
An explicit `Bank` separated mode now refuses a combined file and opens the
bank-only snapshot without constructing SPI/PSP or installing DICT tables. Its
unconverted methods fail closed if they request those embedded objects. The
`SeparatedPixCoordinator` uses a single ecosystem recipient snapshot and the
bank-owned queue/read/apply/ack methods to complete a new queued external Pix
across the two files. A test exports a drained checkpoint, makes that payment,
restarts both processes after SPI commit and after PSP credit, and verifies
idempotent replay and cross-file reconciliation. This proves the queued-Pix
slice, not the full customer/API cutover or the other external money paths.
New pacs.008 messages also bind the receiving account to the destination ISPB
and root. SPI checks that account before moving PI balances; identical retries
retain the binding, and PSP credit checks it again. Bank and split-file
reconciliation detect a changed bound recipient. Legacy messages without the
field remain readable under their original contract.
This is a tested service boundary and an opt-in queued-Pix runtime slice. The
default server still uses in-process SPI/PSP objects; direct Pix, returns and
MED have not moved. The child also runs under the same OS user.
See [process contract evidence](test-evidence/ecosystem-process-2026-11-16.md).

The opt-in separated bank also supports internal Pix through a coordinator
operation. Its DICT fraud-history read comes from the ecosystem child; account
status, active local key flags, risk decisions, holds and postings stay in the
bank file. A direct settlement, reviewer-approved hold and marked-recipient
rejection all pass on bank-only and ecosystem-only files. This does not yet
route the customer API or scheduled Pix through the separated coordinator.
For external Pix risk review, the same coordinator now supports independent
approval without opening the ecosystem database in the bank. The bank keeps
the hold and risk decision; approval fetches a fresh PSP snapshot, queues the
Pix intent, and dispatch completes it. A newly fraud-flagged recipient blocks
approval without releasing the hold. This path is tested but the operator
HTTP route still calls the embedded bank method.
The PSP recipient inbox can now be injected into an opt-in Twin API from the
ecosystem client. Its signed login, scoped notice read and logout all execute
inside the worker's `ecosystem.sqlite` transaction boundary; `bank.sqlite`
retains no `psp_*` table. The normal server and operator provisioning/rotation
paths have not been switched to this client.

The opt-in separated customer API also resolves external Pix keys through a
versioned ecosystem snapshot carrying only the recipient identity and DICT
fraud counters needed for the customer response. The bank still owns lookup
attempts and rate limits. Split export copies the existing limiter state into
`pix_lookup_rate_buckets` in the bank file and leaves the old `dict_rate_buckets`
table out of the ecosystem file. The bank rejects a snapshot bound to another
key. The normal campaign runtime still uses the embedded lookup path.

The customer simulator has an opt-in separated adapter: it receives the
synthetic recipient catalog, a durable Pix dispatcher and SPI availability
through ecosystem IPC. A split-file tick exercised external key lookup and
queued Pix without a PSP table in the bank file. Its public tick reports SPI
availability; it leaves `spi_reconciled` unset until a cross-process verifier
can support that claim. The normal `CampaignRuntime` is still embedded.

The opt-in separated `CampaignRuntime` now also processes due scheduled Pix
and Pix Automatic charges to bank-owned recipient accounts. Before each
bounded due batch it reads DICT fraud history from the ecosystem child, then
passes that evidence to the bank-owned internal Pix transaction. Existing
authorization, retry and charge records remain bank-owned. A split-file
campaign cycle settled both products and repeated without duplicate Pix.
The default server still opens the combined runtime.
The separated runtime also probes DICT health through an ecosystem IPC
response instead of using the bank's local key table as a process-health
signal. Full worker telemetry forwarding remains open.

A dedicated read-only verifier child can now inspect both owned SQLite files
and return the cross-book report over versioned IPC. The separated Sentinel
requires that report plus active cautelar totals from the PSP child; it does
not silently substitute a bank-only reconciliation. The verifier child has no
write operation and refuses non-private files. A changed bank PI mirror raised
`S-LED-02` in a split-file test. The current verifier is a drained-checkpoint
model: in-flight commands can temporarily make the report red. The Sentinel
waits up to 30 real seconds for those commands, persisting the first-seen time
across a scanner restart, while still raising structural drift immediately.
SPI message telemetry forwarding and an exact live
in-flight reconciliation model remain open before the default runtime cutover.

The separated 400,000-history/1,000-external-Pix load now passes on the
bank-only and ecosystem-only files with 1,000 accepted `pacs.008/002` pairs,
zero cautelar holds, risk p95 7.22 ms, and a green drained cross-file report.
See [separated load evidence](test-evidence/separated-interbank-risk-load-2026-11-17.md).
This measures the opt-in coordinator, not the full campaign runtime or its
Sentinel stream.

## External Pix protocol

1. In one bank transaction, evaluate risk, reserve available funds, record a
   unique Pix intent and transactional outbound pacs.008 command, then commit.
   Status is `in_processing`; no final debit or PSP credit is assumed yet.
2. A dispatcher sends the durable command to the SPI process. It may retry
   after a crash. SPI keys the request by EndToEndId and returns the same
   pacs.002 for identical retries; changed payloads fail as conflicts.
3. The bank consumes pacs.002 in one transaction. `ACSC` posts the final bank
   debit and settlement mirror and releases the reservation; `RJCT` releases
   the reservation without posting a transfer. The bank records the response
   ID so duplicate delivery has no second movement. A timeout leaves the
   transfer processing until the SPI outcome is known; it cannot silently
   convert uncertainty into success or failure.
4. The receiving PSP consumes the accepted payment idempotently, credits its
   account and root balance, and decides whether to place a cautelar hold.
   Bank telemetry and customer views derive from committed events, not from
   a synchronous mutation of PSP tables.

Returns and MED need the same durable command/acknowledgement discipline.
The existing stable return ID per MED hop is a prerequisite, but a cross-file
crash can still leave one side committed. Compensation is explicit and
idempotent; it must not rely on a distributed SQLite transaction.

## Migration and acceptance

- Freeze writes at a verified checkpoint, snapshot and seal the existing bank,
  split owned tables into `ecosystem.sqlite`, and compare participant balances,
  root funds, pacs history and bank settlement mirrors before admitting new
  commands. Keep the legacy database read-only for audit; do not infer missing
  history or silently reseed balances.
- Start the ecosystem behind a local authenticated IPC boundary. A bank
  process receives only the `SpiClient` capability, never a SQLite handle to
  `ecosystem.sqlite`. Recipient PSP identities and private notice cursors move
  with their accounts.
- Inject crashes after bank reservation, command dispatch, SPI commit, PSP
  credit, pacs.002 delivery, and final bank posting. Replays must converge to
  one message and one movement on each side. An unavailable SPI leaves a
  visible processing or rejected state according to an explicit timeout policy.
- Repeat the 1,000-payment interbank risk load, 24-hour honest day, MED partial
  recovery and bank/SPI/PSP reconciliation on the separated processes. The
  final gate includes a direct-write denial test and a restart after every
  message boundary.

Current bank telemetry writes use the bank SQLite connection, so a rolled-back
bank transaction also rolls back those records. `TelemetryStream` waits for an
open transaction to close before publishing. A separate telemetry process
would require a transactional bank outbox and idempotent delivery before the
same rollback guarantee could be claimed across processes.
