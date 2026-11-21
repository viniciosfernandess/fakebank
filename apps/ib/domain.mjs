export const START = 540;
export const END = 930;
export const CUTOFF = Object.freeze({ closing: 720, primary: 765, firm: 780, margin: 840 });
export const FACILITY = Object.freeze({ maximum: 2_500_000_000, minutes: 45, feeBps: 8 });

export const scenarios = Object.freeze({
  combined: { name: 'Dia sob pressão', closing: true, matching: true, liquidity: true },
  closing: { name: 'Documento de fechamento em atraso', closing: true },
  matching: { name: 'Divergência na instrução', matching: true },
  liquidity: { name: 'Aumento de chamada de margem', liquidity: true },
  clean: { name: 'Dia sem exceções' },
});

const conditions = {
  indenture: { name: 'Escritura assinada', owner: 'Jurídico', minutes: 55, requires: [] },
  allocation: { name: 'Alocação confirmada', owner: 'Mesa de emissão', requires: [] },
  registration: { name: 'Registro confirmado', owner: 'Custódia', requires: ['indenture'] },
};

const opening = Object.freeze({
  cash: {
    firm: 3_500_000_000, investor: 10_000_000_000, issuer: 0,
    buyer: 12_000_000_000, counterparty: 0, lender: 4_000_000_000,
  },
  'BV-DEB-01': { issuer: 90_000, investor: 0 },
  'BV-DEB-02': { firm: 85_000, buyer: 0 },
});
export const issuance = Object.freeze({
  id: 'BV-DEB-01', issuer: 'Horizonte Infra (simulador)', coordinator: 'Banco Vivo IB',
  priceCents: 100_000, units: 90_000, rateBps: 1_185, maturity: '2031-11-21',
  allocation: Object.freeze({ investor: 'Fundo Horizonte IV (simulador)', units: 90_000 }),
});
const trades = {
  primary: { security: issuance.id, seller: 'issuer', buyer: 'investor', units: issuance.units, cents: issuance.units * issuance.priceCents },
  firm: { security: 'BV-DEB-02', seller: 'firm', buyer: 'buyer', units: 85_000, cents: 8_500_000_000 },
};

function instruction(id, readyAt, custody) {
  const { security, units, cents } = trades[id];
  const terms = { security, units, cents, custody };
  return { readyAt, matched: false, delivered: { ...terms }, received: { ...terms }, settled: null };
}

export function differences(item) {
  return Object.keys(item.delivered).filter((key) => item.delivered[key] !== item.received[key]);
}

export function record(state, code, detail = {}) {
  state.events.push({ id: state.events.length + 1, at: state.now, code, ...detail });
}

export function createDay(scenario = 'combined', policy = 'predictive', market = null) {
  if (!Object.hasOwn(scenarios, scenario) || !['predictive', 'reactive'].includes(policy)) {
    throw new RangeError('Cenário ou política inválida.');
  }
  const state = {
    version: 0,
    scenario,
    policy,
    ...(market === null ? {} : { market }),
    now: START,
    documents: {
      indenture: { eta: 660, received: null, provenance: 'Agenda do emissor' },
      allocation: { eta: START, received: START, provenance: 'Livro alocado' },
      registration: { minutesAfterPrerequisites: 20, received: null, provenance: 'Custódia' },
    },
    release: null,
    instructions: {
      primary: instruction('primary', 730, 'SIM-INV-01'),
      firm: instruction('firm', 755, 'SIM-COMP-01'),
    },
    margin: { amount: 10_000_000_000, paid: null },
    work: { closing: null, matching: null },
    funding: null,
    balance: structuredClone(opening),
    journal: [],
    events: [],
  };
  record(state, 'opened', { scenario, policy });
  return state;
}

export function futureDates(state) {
  const indenture = state.documents.indenture;
  const contract = indenture.received ?? Math.min(indenture.eta, state.work.closing?.doneAt ?? Infinity);
  const registration = state.documents.registration;
  return {
    indenture: contract,
    allocation: state.documents.allocation.received,
    registration: registration.received ?? contract + registration.minutesAfterPrerequisites,
  };
}

function transfer(state, ref, legs) {
  if (state.journal.some((entry) => entry.ref === ref)) throw new Error('Referência contábil repetida.');
  const next = structuredClone(state.balance);
  for (const leg of legs) {
    const { asset, from, to, amount } = leg;
    if (!Number.isSafeInteger(amount) || amount <= 0 || from === to ||
        !Object.hasOwn(next[asset], from) || !Object.hasOwn(next[asset], to)) {
      throw new Error('Lançamento inválido.');
    }
    if (next[asset][from] < amount) return false;
    next[asset][from] -= amount;
    next[asset][to] += amount;
  }
  state.balance = next;
  state.journal.push({ ref, at: state.now, legs });
  return true;
}

export function correction(state) {
  const item = state.instructions.firm;
  const changed = differences(item);
  const record = state.custody;
  const trusted = record === undefined ? true : record.active && record.account === item.delivered.custody;
  const duration = 72;
  return {
    repairable: changed.length === 1 && changed[0] === 'custody' && trusted,
    pending: state.work.matching !== null,
    at: Math.max(item.readyAt, state.now + duration),
    duration,
    authorityRevision: record?.revision ?? 0,
  };
}

function tradeAvailability(state, id) {
  const item = state.instructions[id];
  if (item.settled !== null) return item.settled;
  const repair = id === 'firm' && correction(state);
  if (differences(item).length && (!repair?.repairable || !repair.pending)) return null;
  const repairAt = repair?.pending ? state.work.matching.doneAt : 0;
  const match = item.matched && differences(item).length === 0 ? state.now : Math.max(item.readyAt, repairAt);
  return id === 'primary' ? Math.max(match, state.release ?? futureDates(state).registration) : match;
}

export function forecast(state) {
  const closing = state.release ?? Math.max(...Object.values(futureDates(state)));
  const firm = tradeAvailability(state, 'firm');
  const primary = tradeAvailability(state, 'primary');
  const cash = state.balance.cash.firm;
  const margin = state.margin.paid === null ? state.margin.amount : 0;
  const firmTrade = state.instructions.firm;
  const receipt = firmTrade.settled === null && firm !== null && firm <= CUTOFF.firm &&
    state.balance.cash.buyer >= trades.firm.cents && state.balance[trades.firm.security].firm >= trades.firm.units
    ? trades.firm.cents : 0;
  const pendingFunding = state.funding && !state.funding.arrived && !state.funding.failed && !state.facilityUnavailable && state.funding.at <= CUTOFF.margin
    ? state.funding.net : 0;
  const cashWithoutTrade = cash + pendingFunding;
  const gap = Math.max(0, margin - cashWithoutTrade - receipt);
  const latest = CUTOFF.margin - FACILITY.minutes;
  const draw = Math.min(state.facilityUnavailable ? 0 : Math.min(FACILITY.maximum, state.balance.cash.lender), Math.ceil(gap * 10_000 / (10_000 - FACILITY.feeBps)));
  const fee = Math.ceil(draw * FACILITY.feeBps / 10_000);
  return {
    documents: Object.entries(conditions).map(([id, condition]) =>
      ({ id, ...condition, ...state.documents[id], forecast: futureDates(state)[id] })),
    closing, firm, primary, cash, receipt, pendingFunding, cashWithoutTrade, gap, latest,
    draw, fee, residual: Math.max(0, gap - draw + fee),
    margin, facility: FACILITY,
  };
}

function observe(state) {
  const fixture = scenarios[state.scenario];
  const market = state.market ?? {};
  if (fixture.closing && state.now === (market.closingSignal ?? 610)) {
    state.documents.indenture.eta = market.indentureEta ?? 742;
    state.documents.indenture.provenance = 'Contraparte jurídica atualizou a entrega';
    record(state, 'closing-delay', { eta: state.documents.indenture.eta, condition: 'indenture' });
  }
  if (fixture.matching && state.now === (market.matchingSignal ?? 685) && state.instructions.firm.settled === null) {
    state.instructions.firm.received.custody = 'SIM-COMP-09';
    state.instructions.firm.matched = false;
    state.custody = { account: state.instructions.firm.delivered.custody, active: !market.ssiUnconfirmed, revision: 1 };
    record(state, 'instruction-mismatch', { trade: 'firm', field: 'Conta de custódia' });
  }
  if (fixture.liquidity && state.now === (market.marginSignal ?? 740)) {
    state.margin.amount = market.marginAmount ?? 13_500_000_000;
    record(state, 'margin-update', { amount: state.margin.amount });
  }
  if (state.now === market.ssiWithdrawAt && state.instructions.firm.settled === null && state.custody?.active) {
    state.custody.active = false;
    state.custody.revision += 1;
    state.instructions.firm.matched = false;
    record(state, 'custody-authority-withdrawn', { trade: 'firm' });
  }
  if (state.now === market.facilityDownAt) {
    state.facilityUnavailable = true;
    record(state, 'facility-unavailable');
  }

}

export function actions(state) {
  const view = forecast(state);
  if (state.now >= END) return [];
  const result = [];
  const anticipate = state.policy === 'predictive';
  if (state.release === null && state.work.closing === null &&
      state.documents.indenture.received === null &&
      view.closing > CUTOFF.closing && (anticipate || state.now >= CUTOFF.closing)) {
    result.push({ id: 'closing', cause: 'Escritura atrasa a liberação da emissão', deadline: CUTOFF.closing,
      completion: state.now + conditions.indenture.minutes,
      useful: state.now + conditions.indenture.minutes < state.documents.indenture.eta });
  }
  const repair = correction(state);
  if (repair.repairable && !repair.pending &&
      (anticipate || state.now >= CUTOFF.firm)) {
    result.push({ id: 'matching', cause: 'Conta de custódia divergente', deadline: CUTOFF.firm,
      completion: state.now + repair.duration, useful: true });
  }
  if (view.draw > 0 && !state.funding && (anticipate || state.now >= CUTOFF.margin)) {
    result.push({ id: 'funding', cause: 'Caixa próprio projetado abaixo da chamada',
      deadline: CUTOFF.margin, latest: view.latest,
      completion: state.now + FACILITY.minutes, useful: true });
  }
  return result.filter((item) => item.useful || state.now < item.deadline);
}

export function startWork(state, id, decision = null) {
  const action = actions(state).find((item) => item.id === id);
  if (!action) throw new RangeError('Ação indisponível para o estado atual.');
  if (id === 'funding') {
    const { draw, fee } = forecast(state);
    state.funding = { requested: state.now, at: action.completion, draw, fee, net: draw - fee, arrived: false };
    record(state, 'funding-requested', { amount: draw, fee, due: action.completion, cause: action.cause, ...(decision && { decision }) });
    return;
  }
  state.work[id] = {
    started: state.now,
    doneAt: action.completion,
    ...(id === 'matching' && { authorityRevision: correction(state).authorityRevision }),
  };
  record(state, id === 'closing' ? 'closing-expedited' : 'matching-repair-started',
    { due: action.completion, cause: action.cause, ...(decision && { decision }) });
}

function settle(state, id) {
  const instruction = state.instructions[id];
  if (instruction.settled !== null || !instruction.matched || differences(instruction).length ||
      (id === 'firm' && state.custody?.active === false) || state.now > CUTOFF[id] ||
      (id === 'primary' && state.release === null)) return;
  const { buyer, seller, units, cents, security } = trades[id];
  const committed = transfer(state, id, [
    { asset: 'cash', from: buyer, to: seller, amount: cents },
    { asset: security, from: seller, to: buyer, amount: units },
  ]);
  if (committed) {
    instruction.settled = state.now;
    record(state, 'settled', { trade: id, security, units, amount: cents });
  }
}

export function processMinute(state) {
  observe(state);
  for (const [id, due] of Object.entries(futureDates(state))) {
    if (state.documents[id].received === null && due <= state.now) {
      state.documents[id].received = state.now;
      record(state, 'document-received', { condition: id });
    }
  }
  if (state.release === null && Object.values(state.documents).every((doc) => doc.received !== null)) {
    state.release = state.now;
    record(state, 'closing-released');
  }
  const repair = state.work.matching;
  if (repair?.doneAt === state.now) {
    const current = correction(state);
    if (current.repairable && (repair.authorityRevision ?? 0) === current.authorityRevision) {
      state.instructions.firm.received.custody = state.instructions.firm.delivered.custody;
      record(state, 'instruction-corrected', { trade: 'firm' });
    } else {
      state.work.matching = null;
      record(state, 'instruction-repair-rejected', { trade: 'firm' });
    }
  }
  const facility = state.funding;
  if (facility && !facility.arrived && facility.at === state.now) {
    if (state.facilityUnavailable || !transfer(state, 'funding', [
      { asset: 'cash', from: 'lender', to: 'firm', amount: facility.draw },
      { asset: 'cash', from: 'firm', to: 'lender', amount: facility.fee },
    ])) {
      facility.failed = true;
      record(state, 'funding-failed', { amount: facility.net });
    } else {
      facility.arrived = true;
      record(state, 'funding-arrived', { amount: facility.net, fee: facility.fee, principal: facility.draw });
    }
  }
  for (const [id, instruction] of Object.entries(state.instructions)) {
    if (!instruction.matched && differences(instruction).length === 0 && instruction.readyAt <= state.now) {
      instruction.matched = true;
      record(state, 'matched', { trade: id });
    }
    settle(state, id);
    if (state.now === CUTOFF[id] && instruction.settled === null) {
      const cause = !instruction.matched ? 'Instrução sem conciliação' :
        id === 'primary' && state.release === null ? 'Emissão sem liberação' : 'Caixa ou posição indisponível';
      record(state, 'settlement-missed', { trade: id, cause });
    }
  }
  if (state.now === CUTOFF.closing && state.release === null) record(state, 'closing-missed');
  if (state.now >= CUTOFF.margin && state.margin.paid === null) {
    if (transfer(state, 'margin', [{ asset: 'cash', from: 'firm', to: 'counterparty', amount: state.margin.amount }])) {
      state.margin.paid = state.now;
      record(state, 'margin-paid', { amount: state.margin.amount });
    } else if (state.now === CUTOFF.margin) {
      record(state, 'margin-missed', { amount: state.margin.amount, gap: state.margin.amount - state.balance.cash.firm });
    }
  }
}

function runReactivePolicy(state) {
  // The benchmark baseline uses the same execution gate after formal deadlines.
  for (const id of ['closing', 'matching', 'funding']) {
    if (actions(state).some((action) => action.id === id)) startWork(state, id);
  }
}

export function applyCommand(current, command) {
  const state = structuredClone(current);
  if (command.type === 'act') {
    if (state.now >= END) throw new RangeError('Dia encerrado.');
    startWork(state, command.id);
  } else if (command.type === 'advance') {
    const { minutes, automatic } = command;
    if (!Number.isInteger(minutes) || minutes < 1 || minutes > END - START ||
        typeof automatic !== 'boolean' || state.now >= END) throw new RangeError('Avanço inválido.');
    const to = Math.min(END, state.now + minutes);
    if (automatic && state.policy !== 'reactive') throw new RangeError('Use o executor de agentes para a política preditiva.');
    if (automatic) runReactivePolicy(state);
    while (state.now < to) {
      state.now += 1;
      processMinute(state);
      if (automatic) runReactivePolicy(state);
    }
  } else {
    throw new RangeError('Comando desconhecido.');
  }
  state.version += 1;
  return state;
}

export function outcomes(state) {
  const balances = structuredClone(opening);
  for (const { legs } of state.journal) {
    for (const { asset, from, to, amount } of legs) {
      balances[asset][from] -= amount;
      balances[asset][to] += amount;
    }
  }
  const reconciled = Object.entries(balances).every(([asset, entries]) =>
    Object.entries(entries).every(([account, value]) =>
      value >= 0 && value === state.balance[asset][account]));
  return {
    closing: state.release !== null && state.release <= CUTOFF.closing,
    primary: state.instructions.primary.settled !== null && state.instructions.primary.settled <= CUTOFF.primary,
    firm: state.instructions.firm.settled !== null && state.instructions.firm.settled <= CUTOFF.firm,
    margin: state.margin.paid !== null && state.margin.paid <= CUTOFF.margin,
    cost: state.funding?.arrived ? state.funding.fee : 0,
    reconciled,
  };
}

export function presentation(state) {
  const { market: _future, ...visible } = state;
  return {
    ...visible, issuance, cutoff: CUTOFF, end: END,
    instructions: Object.fromEntries(Object.entries(state.instructions).map(([id, item]) =>
      [id, { ...item, differences: differences(item) }])),
    forecast: forecast(state), actions: actions(state), outcomes: outcomes(state),
  };
}

export function summarize(state) {
  return { ...outcomes(state),
    closingAt: state.release, primaryAt: state.instructions.primary.settled,
    firmAt: state.instructions.firm.settled, marginAt: state.margin.paid,
    actions: state.events.filter(({ code }) => ['closing-expedited', 'matching-repair-started', 'funding-requested'].includes(code)),
    misses: state.events.filter(({ code }) => code.endsWith('-missed')),
  };
}
