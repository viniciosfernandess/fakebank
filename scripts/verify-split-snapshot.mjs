import { DatabaseSync } from "node:sqlite";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const JACARANDA_ISPB = "12345678";
const POSTED = new Set(["settled", "returned_partial", "returned_full"]);

function count(db, sql) { return db.prepare(sql).get().n; }

function hasTable(db, name) {
  return Boolean(db.prepare(`SELECT 1 FROM sqlite_master
    WHERE type='table' AND name=?`).get(name));
}

function message(db, endToEndId, type) {
  const row = db.prepare(`SELECT payload_json FROM spi_messages
    WHERE end_to_end_id=? AND message_type=? ORDER BY id LIMIT 1`)
    .get(endToEndId, type);
  if (!row) return null;
  try { return JSON.parse(row.payload_json); }
  catch { return null; }
}

export function verifySplitSnapshots(bankPath, ecosystemPath) {
  const bank = new DatabaseSync(resolve(bankPath), { readOnly: true });
  let ecosystem;
  try {
    ecosystem = new DatabaseSync(resolve(ecosystemPath), { readOnly: true });
    bank.exec("PRAGMA query_only=ON; BEGIN");
    ecosystem.exec("PRAGMA query_only=ON; BEGIN");
    const bankSchemaDrift = count(bank, `SELECT COUNT(*) n FROM sqlite_master
      WHERE type='table' AND (name GLOB 'spi_*' OR name GLOB 'psp_*'
        OR name GLOB 'dict_*')`);
    const ecosystemSchemaDrift = count(ecosystem, `SELECT COUNT(*) n FROM sqlite_master
      WHERE type='table' AND name IN ('accounts','ledger_entries','pix_transfers')`);
    const bankPiRow = bank.prepare(`SELECT balance_cached FROM accounts
      WHERE system_role='pix_settlement'`).get();
    const spiPiRow = ecosystem.prepare(`SELECT pi_balance_cents FROM spi_participants
      WHERE ispb=?`).get(JACARANDA_ISPB);
    const bankPiCents = bankPiRow ? -bankPiRow.balance_cached : null;
    const spiPiCents = spiPiRow?.pi_balance_cents ?? null;
    const ledgerDrift = count(bank, `SELECT COALESCE(SUM(ABS(a.balance_cached-
      COALESCE(l.total,0))),0) n FROM accounts a LEFT JOIN
      (SELECT account_id,SUM(amount) total FROM ledger_entries GROUP BY account_id) l
      ON l.account_id=a.id`);
    const pendingPix = count(bank, `SELECT COUNT(*) n FROM pix_transfers
      WHERE status='in_processing'`);
    const pendingInbound = count(bank, `SELECT COUNT(*) n FROM pix_psp_inbound_outbox
      WHERE acknowledged_at IS NULL`);
    const pspAccountDrift = count(ecosystem, `SELECT COUNT(*) n FROM psp_accounts a LEFT JOIN
      (SELECT account_id,SUM(available_cents) total FROM psp_funds GROUP BY account_id) f
      ON f.account_id=a.id WHERE a.balance_cents<>COALESCE(f.total,0)`);
    const rootOverflow = count(ecosystem, `SELECT COUNT(*) n FROM
      (SELECT root_transfer_id,SUM(available_cents) total FROM psp_funds GROUP BY root_transfer_id) f
      LEFT JOIN psp_roots r ON r.root_transfer_id=f.root_transfer_id
      WHERE r.root_transfer_id IS NULL OR f.total>r.amount_cents`);
    const pspAccounts = new Map(ecosystem.prepare("SELECT id,ispb FROM psp_accounts")
      .all().map((account) => [account.id, account.ispb]));
    const rootFor = ecosystem.prepare(`SELECT end_to_end_id,account_id,amount_cents,source
      FROM psp_roots WHERE root_transfer_id=?`);
    const receiptFor = ecosystem.prepare(`SELECT end_to_end_id,account_id,amount_cents
      FROM psp_inbound_receipts WHERE root_transfer_id=?`);
    const senderFor = ecosystem.prepare(`SELECT sender_account,settled_at
      FROM psp_inbound_sender_facts WHERE root_transfer_id=?`);
    const pixFor = bank.prepare(`SELECT id,end_to_end_id,from_account,to_account,amount,
      status,settled_at FROM pix_transfers WHERE id=?`);
    const commandFor = bank.prepare(`SELECT end_to_end_id,from_ispb,to_ispb,amount_cents,
      deadline_at_real,response_status,response_reason FROM pix_spi_outbox
      WHERE transfer_id=?`);
    const inboundFor = bank.prepare(`SELECT end_to_end_id,to_account,amount_cents,
      from_account,settled_at,acknowledged_at FROM pix_psp_inbound_outbox
      WHERE transfer_id=?`);
    let externalTransfers = 0;
    let transferDrift = 0;
    let spiMessageDrift = 0;
    let commandDrift = 0;
    let pendingSpiCents = 0;
    for (const pix of bank.prepare(`SELECT id,end_to_end_id,from_account,to_account,amount,
      status,settled_at,spi_command_version FROM pix_transfers`).iterate()) {
      const recipientIspb = pspAccounts.get(pix.to_account);
      if (!recipientIspb) continue;
      externalTransfers++;
      const root = rootFor.get(pix.id);
      const receipt = receiptFor.get(pix.id);
      const posted = POSTED.has(pix.status);
      if (posted) {
        if (!root || root.end_to_end_id !== pix.end_to_end_id ||
          root.account_id !== pix.to_account || root.amount_cents !== pix.amount ||
          (root.source === "receipt" && (!receipt ||
            receipt.end_to_end_id !== pix.end_to_end_id ||
            receipt.account_id !== pix.to_account ||
            receipt.amount_cents !== pix.amount))) transferDrift++;
        if (receipt) {
          const sender = senderFor.get(pix.id);
          if (receipt.end_to_end_id !== pix.end_to_end_id ||
            receipt.account_id !== pix.to_account || receipt.amount_cents !== pix.amount ||
            sender?.sender_account !== pix.from_account ||
            sender?.settled_at !== pix.settled_at) transferDrift++;
        }
      } else if (root || receipt) transferDrift++;
      const request = message(ecosystem, pix.end_to_end_id, "pacs.008");
      const response = message(ecosystem, pix.end_to_end_id, "pacs.002");
      const pending = pix.status === "in_processing";
      const noSpiMessagesYet = pending && !request && !response;
      const messagesMatch = Boolean(request && response &&
        request.type === "pacs.008" && request.from_ispb === JACARANDA_ISPB &&
        request.to_ispb === recipientIspb && request.amount_cents === pix.amount &&
        (request.root_transfer_id === undefined || request.root_transfer_id === pix.id) &&
        (request.recipient_account === undefined ||
          request.recipient_account === pix.to_account) &&
        response.type === "pacs.002" && response.from_ispb === JACARANDA_ISPB &&
        response.to_ispb === recipientIspb && response.amount_cents === pix.amount &&
        (pending ? ["ACSC", "RJCT"].includes(response.status) :
          response.status === (posted ? "ACSC" : "RJCT")));
      if (!noSpiMessagesYet && !messagesMatch) spiMessageDrift++;
      const command = commandFor.get(pix.id);
      const commandMatches = Boolean(command &&
        command.end_to_end_id === pix.end_to_end_id &&
        command.from_ispb === JACARANDA_ISPB &&
        command.to_ispb === recipientIspb && command.amount_cents === pix.amount &&
        (pending ? command.response_status === null && command.response_reason === null :
          command.response_status === (posted ? "ACSC" : "RJCT") &&
          command.response_status === response?.status &&
          command.response_reason === (response?.reason ?? null)) &&
        (pending && !request ||
          command.deadline_at_real === (request?.deadline_at_real ?? null)));
      if (pix.spi_command_version > 0 && !commandMatches) commandDrift++;
      if (pending && messagesMatch && commandMatches && response.status === "ACSC") {
        pendingSpiCents += pix.amount;
        if (!Number.isSafeInteger(pendingSpiCents))
          throw new Error("CROSS_BOOK_PENDING_SPI_AMOUNT_INVALID");
      }
      const inbound = inboundFor.get(pix.id);
      if (pix.spi_command_version === 2 && posted && (!inbound ||
        inbound.end_to_end_id !== pix.end_to_end_id ||
        inbound.to_account !== pix.to_account || inbound.amount_cents !== pix.amount ||
        inbound.from_account !== pix.from_account ||
        inbound.settled_at !== pix.settled_at || !inbound.acknowledged_at ||
        !receipt)) commandDrift++;
      if (!posted && inbound) commandDrift++;
    }
    for (const root of ecosystem.prepare(`SELECT root_transfer_id,end_to_end_id,
      account_id,amount_cents FROM psp_roots`).iterate()) {
      const pix = pixFor.get(root.root_transfer_id);
      if (!pix || !POSTED.has(pix.status) ||
        pix.end_to_end_id !== root.end_to_end_id ||
        pix.to_account !== root.account_id || pix.amount !== root.amount_cents)
        transferDrift++;
    }
    for (const receipt of ecosystem.prepare(`SELECT root_transfer_id,end_to_end_id,
      account_id,amount_cents FROM psp_inbound_receipts`).iterate()) {
      const pix = pixFor.get(receipt.root_transfer_id);
      if (!pix || !POSTED.has(pix.status) ||
        pix.end_to_end_id !== receipt.end_to_end_id ||
        pix.to_account !== receipt.account_id || pix.amount !== receipt.amount_cents)
        transferDrift++;
    }
    let pendingReturns = 0;
    let returnCommandDrift = 0;
    const returnTable = hasTable(bank, "pix_psp_return_outbox");
    const resultTable = hasTable(ecosystem, "psp_pix_return_results");
    const returnCommands = returnTable ? bank.prepare(
      "SELECT * FROM pix_psp_return_outbox").all() : [];
    const returnResults = resultTable ? ecosystem.prepare(
      "SELECT * FROM psp_pix_return_results").all() : [];
    const resultsById = new Map(returnResults.map((row) => [row.return_id, row]));
    const commandIds = new Set();
    const bankReturn = bank.prepare(`SELECT transfer_id,amount,reason,status
      FROM pix_returns WHERE id=?`);
    for (const command of returnCommands) {
      commandIds.add(command.id);
      if (!command.acknowledged_at && !command.rejected_at) pendingReturns++;
      const result = resultsById.get(command.id);
      const pix = pixFor.get(command.transfer_id);
      if (!pix || pix.end_to_end_id !== command.end_to_end_id ||
        pix.to_account !== command.recipient_account ||
        command.reason !== "ordinary" ||
        (command.acknowledged_at || command.rejected_at) && !result) {
        returnCommandDrift++;
        continue;
      }
      if (!result) continue;
      if (result.root_transfer_id !== command.transfer_id ||
        result.end_to_end_id !== command.end_to_end_id ||
        result.account_id !== command.recipient_account ||
        result.amount_cents !== command.amount_cents ||
        result.reason !== command.reason ||
        result.created_at !== command.created_at ||
        (command.acknowledged_at && result.outcome !== "accepted") ||
        (command.rejected_at && (result.outcome !== "rejected" ||
          result.failure_reason !== command.failure_reason))) returnCommandDrift++;
      const settled = bankReturn.get(command.id);
      if (command.acknowledged_at ?
        !settled || settled.transfer_id !== command.transfer_id ||
          settled.amount !== command.amount_cents ||
          settled.reason !== command.reason ||
          !["returned_partial", "returned_full"].includes(settled.status) :
        Boolean(settled)) returnCommandDrift++;
      const receipts = ecosystem.prepare(`SELECT payload_json FROM spi_messages
        WHERE end_to_end_id=? AND message_type='pacs.004'`).all(command.end_to_end_id)
        .map((row) => { try { return JSON.parse(row.payload_json); }
          catch { return null; } });
      const receipt = receipts.find((row) => row?.return_id === command.id);
      if (result.outcome === "accepted" ?
        !receipt || receipt.amount_cents !== command.amount_cents ||
          receipt.to_ispb !== JACARANDA_ISPB ||
          receipt.from_ispb !== pspAccounts.get(command.recipient_account) ||
          receipt.reason !== command.reason : Boolean(receipt))
        returnCommandDrift++;
    }
    for (const result of returnResults)
      if (!commandIds.has(result.return_id)) returnCommandDrift++;
    let pendingCautelarReturns = 0;
    let cautelarReturnDrift = 0;
    const cautelarTable = hasTable(bank, "pix_psp_cautelar_return_outbox");
    const cautelarResultTable = hasTable(ecosystem, "psp_cautelar_return_results");
    const cautelarCommands = cautelarTable ? bank.prepare(
      "SELECT * FROM pix_psp_cautelar_return_outbox").all() : [];
    const cautelarResults = cautelarResultTable ? ecosystem.prepare(
      "SELECT * FROM psp_cautelar_return_results").all() : [];
    const cautelarById = new Map(cautelarResults.map((row) => [row.return_id, row]));
    const cautelarIds = new Set();
    const holdFor = ecosystem.prepare(`SELECT root_transfer_id,account_id,
      amount_cents,status,resolved_by FROM psp_cautelar_holds WHERE id=?`);
    for (const command of cautelarCommands) {
      cautelarIds.add(command.id);
      if (!command.acknowledged_at && !command.rejected_at)
        pendingCautelarReturns++;
      const result = cautelarById.get(command.id);
      const pix = pixFor.get(command.transfer_id);
      const hold = holdFor.get(command.hold_id);
      if (!pix || !hold || pix.end_to_end_id !== command.end_to_end_id ||
        pix.to_account !== command.recipient_account ||
        hold.root_transfer_id !== command.transfer_id ||
        hold.account_id !== command.recipient_account ||
        hold.amount_cents !== command.amount_cents ||
        ((command.acknowledged_at || command.rejected_at) && !result)) {
        cautelarReturnDrift++;
        continue;
      }
      if (!result) continue;
      if (result.hold_id !== command.hold_id ||
        result.root_transfer_id !== command.transfer_id ||
        result.end_to_end_id !== command.end_to_end_id ||
        result.account_id !== command.recipient_account ||
        result.amount_cents !== command.amount_cents ||
        result.actor !== command.actor || result.created_at !== command.created_at ||
        (command.acknowledged_at && result.outcome !== "accepted") ||
        (command.rejected_at && (result.outcome !== "rejected" ||
          result.failure_reason !== command.failure_reason))) cautelarReturnDrift++;
      const settled = bankReturn.get(command.id);
      if (command.acknowledged_at ?
        !settled || settled.transfer_id !== command.transfer_id ||
          settled.amount !== command.amount_cents || settled.reason !== "cautelar" ||
          !["returned_partial", "returned_full"].includes(settled.status) :
        Boolean(settled)) cautelarReturnDrift++;
      const receipts = ecosystem.prepare(`SELECT payload_json FROM spi_messages
        WHERE end_to_end_id=? AND message_type='pacs.004'`)
        .all(command.end_to_end_id)
        .map((row) => { try { return JSON.parse(row.payload_json); }
          catch { return null; } });
      const receipt = receipts.find((row) => row?.return_id === command.id);
      const returnNotice = ecosystem.prepare(`SELECT 1 FROM psp_cautelar_notices
        WHERE hold_id=? AND kind='returned' AND amount_cents=?`).get(
          command.hold_id, command.amount_cents);
      if (result.outcome === "accepted" ?
        !receipt || receipt.amount_cents !== command.amount_cents ||
          receipt.to_ispb !== JACARANDA_ISPB ||
          receipt.from_ispb !== pspAccounts.get(command.recipient_account) ||
          receipt.reason !== "cautelar" || !returnNotice ||
          hold.status !== "returned" ||
          hold.resolved_by !== command.actor : Boolean(receipt))
        cautelarReturnDrift++;
    }
    for (const result of cautelarResults)
      if (!cautelarIds.has(result.return_id)) cautelarReturnDrift++;
    const bankHop = bank.prepare(`SELECT case_id,root_transfer_id,account_id,
      blocked_cents,refunded_cents,created_at,released_at FROM med_hops WHERE id=?`);
    const pspHop = ecosystem.prepare(`SELECT case_id,root_transfer_id,account_id,
      blocked_cents,refunded_cents,created_at,released_at FROM psp_med_holds WHERE hop_id=?`);
    let medHoldDrift = 0;
    for (const hop of bank.prepare("SELECT * FROM med_hops").iterate()) {
      const mirror = pspHop.get(hop.id);
      if (!mirror || ["case_id", "root_transfer_id", "account_id", "blocked_cents",
        "refunded_cents", "created_at", "released_at"].some((field) =>
        mirror[field] !== hop[field])) medHoldDrift++;
    }
    for (const hop of ecosystem.prepare("SELECT hop_id FROM psp_med_holds").iterate())
      if (!bankHop.get(hop.hop_id)) medHoldDrift++;
    let medCommandDrift = 0;
    let pendingMed = 0;
    for (const command of [
      { bank: "med_psp_open_outbox", worker: "psp_med_case_openings",
        fields: ["case_id", "transfer_id", "claim_amount_cents", "created_at"],
        workerFields: ["case_id", "root_transfer_id", "claim_amount_cents", "created_at"] },
      { bank: "med_psp_release_outbox", worker: "psp_med_case_releases",
        fields: ["case_id", "transfer_id", "created_at"],
        workerFields: ["case_id", "root_transfer_id", "released_at"] },
      { bank: "med_psp_settlement_outbox", worker: "psp_med_case_settlements",
        fields: ["case_id", "transfer_id", "end_to_end_id",
          "claim_amount_cents", "created_at"],
        workerFields: ["case_id", "root_transfer_id", "end_to_end_id",
          "claim_amount_cents", "settled_at"] },
    ]) {
      const bankTable = hasTable(bank, command.bank);
      const workerTable = hasTable(ecosystem, command.worker);
      if (!bankTable) {
        if (workerTable) medCommandDrift += count(ecosystem,
          `SELECT COUNT(*) n FROM ${command.worker}`);
        continue;
      }
      const bankRows = bank.prepare(`SELECT * FROM ${command.bank}`).all();
      const workerRows = workerTable ? ecosystem.prepare(
        `SELECT * FROM ${command.worker}`).all() : [];
      const byCase = new Map(workerRows.map((row) => [row.case_id, row]));
      const bankCases = new Set();
      for (const row of bankRows) {
        bankCases.add(row.case_id);
        if (!row.acknowledged_at) pendingMed++;
        const workerRow = byCase.get(row.case_id);
        if (row.acknowledged_at && !workerRow) { medCommandDrift++; continue; }
        if (workerRow && command.fields.some((field, index) =>
          row[field] !== workerRow[command.workerFields[index]])) medCommandDrift++;
      }
      for (const workerRow of workerRows)
        if (!bankCases.has(workerRow.case_id)) medCommandDrift++;
    }
    if (hasTable(bank, "med_dict_analysis_outbox") ||
      hasTable(bank, "med_dict_analyses") ||
      hasTable(ecosystem, "dict_med_analyses")) {
      const bankRows = hasTable(bank, "med_dict_analyses") ?
        bank.prepare("SELECT case_id,analysed_at FROM med_dict_analyses").all() : [];
      const workerRows = hasTable(ecosystem, "dict_med_analyses") ?
        ecosystem.prepare(`SELECT case_id,root_transfer_id,approved_at,analysed_at
          FROM dict_med_analyses`).all() : [];
      const byCase = new Map(workerRows.map((row) => [row.case_id, row]));
      const bankCases = new Set(bankRows.map((row) => row.case_id));
      const analysisCommands = hasTable(bank, "med_dict_analysis_outbox") ?
        new Map(bank.prepare(`SELECT case_id,transfer_id,approved_at,acknowledged_at
          FROM med_dict_analysis_outbox`).all().map((row) => [row.case_id, row])) :
        new Map();
      for (const command of analysisCommands.values()) {
        if (!command.acknowledged_at) pendingMed++;
        else if (!bankCases.has(command.case_id)) medCommandDrift++;
      }
      for (const row of bankRows) {
        const worker = byCase.get(row.case_id);
        const command = analysisCommands.get(row.case_id);
        if (!worker || !command || worker.analysed_at !== row.analysed_at ||
          worker.root_transfer_id !== command.transfer_id ||
          worker.approved_at !== command.approved_at ||
          !command.acknowledged_at) medCommandDrift++;
      }
      for (const worker of workerRows) {
        if (bankCases.has(worker.case_id)) continue;
        const command = analysisCommands.get(worker.case_id);
        if (!command || command.acknowledged_at ||
          worker.root_transfer_id !== command.transfer_id ||
          worker.approved_at !== command.approved_at ||
          worker.analysed_at < command.approved_at) medCommandDrift++;
      }
    }
    if (hasTable(bank, "med_psp_refund_steps") ||
      hasTable(ecosystem, "dict_med_refund_requests")) {
      const bankSteps = hasTable(bank, "med_psp_refund_steps") ?
        bank.prepare("SELECT * FROM med_psp_refund_steps").all() : [];
      const workerSteps = hasTable(ecosystem, "dict_med_refund_requests") ?
        ecosystem.prepare("SELECT * FROM dict_med_refund_requests").all() : [];
      const key = (row) => `${row.case_id}:${row.ispb}`;
      const workerByKey = new Map(workerSteps.map((row) => [key(row), row]));
      const bankKeys = new Set(bankSteps.map(key));
      const settlement = hasTable(bank, "med_psp_settlement_outbox") ?
        new Map(bank.prepare(`SELECT case_id,acknowledged_at
          FROM med_psp_settlement_outbox`).all().map((row) => [row.case_id, row])) :
        new Map();
      const fields = ["case_id", "ispb", "sequence", "requested_at", "deadline_at",
        "processed_at", "refunded_cents"];
      for (const row of bankSteps) {
        const worker = workerByKey.get(key(row));
        if (!worker || fields.some((field) => row[field] !== worker[field]))
          medCommandDrift++;
      }
      for (const row of workerSteps)
        if (!bankKeys.has(key(row)) && settlement.get(row.case_id)?.acknowledged_at)
          medCommandDrift++;
    }
    const report = { bank_pi_cents: bankPiCents, spi_pi_cents: spiPiCents,
      pending_spi_cents: pendingSpiCents,
      external_transfers: externalTransfers, pending_pix: pendingPix,
      pending_inbound: pendingInbound, pending_med: pendingMed,
      pending_returns: pendingReturns,
      pending_cautelar_returns: pendingCautelarReturns,
      bank_schema_drift: bankSchemaDrift,
      ecosystem_schema_drift: ecosystemSchemaDrift, ledger_drift: ledgerDrift,
      psp_account_drift: pspAccountDrift, root_overflow: rootOverflow,
      transfer_drift: transferDrift, spi_message_drift: spiMessageDrift,
      command_drift: commandDrift, return_command_drift: returnCommandDrift,
      cautelar_return_drift: cautelarReturnDrift,
      med_hold_drift: medHoldDrift, med_command_drift: medCommandDrift };
    return { ...report, ok: bankPiCents !== null && spiPiCents !== null &&
      bankPiCents - spiPiCents === pendingSpiCents &&
      Object.entries(report).every(([key, value]) => ["bank_pi_cents", "spi_pi_cents",
        "external_transfers", "pending_spi_cents"].includes(key) || value === 0) };
  } finally {
    if (ecosystem?.isTransaction) ecosystem.exec("ROLLBACK");
    if (bank.isTransaction) bank.exec("ROLLBACK");
    ecosystem?.close(); bank.close();
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  if (process.argv.length !== 4) {
    process.stderr.write("Usage: node scripts/verify-split-snapshot.mjs <bank.sqlite> <ecosystem.sqlite>\n");
    process.exitCode = 2;
  } else {
    try {
      const report = verifySplitSnapshots(process.argv[2], process.argv[3]);
      process.stdout.write(JSON.stringify(report) + "\n");
      if (!report.ok) process.exitCode = 1;
    } catch (error) {
      process.stderr.write(`${error.message}\n`);
      process.exitCode = 1;
    }
  }
}
