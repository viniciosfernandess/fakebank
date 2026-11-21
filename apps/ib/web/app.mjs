const get = (id) => document.getElementById(id);
const formatMoney = new Intl.NumberFormat('pt-BR', { style: 'currency', currency: 'BRL' });
const formatNumber = new Intl.NumberFormat('pt-BR');
const brl = (cents) => formatMoney.format(cents / 100);
const time = (minute) => minute === null || minute === undefined ? '—' :
  `${String(Math.floor(minute / 60)).padStart(2, '0')}:${String(minute % 60).padStart(2, '0')}`;
const instrument = { primary: 'Alocação primária', firm: 'Posição própria do IB' };
const account = { firm: 'IB', investor: 'Investidor', issuer: 'Emissor', buyer: 'Comprador',
  counterparty: 'Contraparte', lender: 'Financiador' };
const deskLabels = { closing: 'Emissão', settlement: 'Liquidação', treasury: 'Tesouraria' };
const reasons = {
  'closing-preserved': 'aceleração preserva o fechamento',
  'primary-protected': 'aceleração preserva a liquidação primária',
  'settlement-preserved': 'correção autorizada preserva a liquidação',
  'funding-sized': 'captação dimensionada para o déficit',
  'conditional-receipt': 'cobertura depende de um crédito ainda não liquidado',
  'repair-before-funding': 'há tempo para resolver a divergência antes de captar',
  'closing-cutoff-missed': 'corte de fechamento perdido',
  'closing-unrecoverable': 'aceleração disponível não preserva a liquidação primária',
  'instruction-not-authorized': 'instrução sem confirmação vigente',
  'settlement-unrecoverable': 'correção não chega a tempo do corte',
  'funding-already-committed': 'linha já solicitada e falta cobertura',
  'funding-window-closed': 'janela de captação encerrada',
  'facility-unavailable': 'linha indisponível',
  unavailable: 'agente indisponível',
  'valid-reply': 'agente voltou a responder',
  'invalid-proposal': 'proposta descartada pelo controle',
};
const actionNames = { closing: 'Antecipar escritura', matching: 'Corrigir e conciliar', funding: 'Solicitar caixa' };
const benchmarkActions = {
  'closing-expedited': () => 'escritura antecipada',
  'matching-repair-started': () => 'correção da instrução iniciada',
  'funding-requested': (action) => `solicitação de ${brl(action.amount)}`,
};
let state;
let busy = false;
let cases = [];

async function api(path, data) {
  const response = await fetch(path, data === undefined ? {} : {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data),
  });
  const body = await response.json();
  if (!response.ok) throw Object.assign(new Error(body.error), { status: response.status });
  return body;
}

function fail(message = '') {
  const notice = get('error');
  notice.hidden = !message;
  notice.textContent = message;
}

function row(label, value, info = '') {
  return `<div><dt>${label}${info ? `<small>${info}</small>` : ''}</dt><dd>${value}</dd></div>`;
}

function setDesk(id, name, status, metric, description, rows) {
  const desk = get(id);
  const [tone, label] = status;
  desk.dataset.tone = tone;
  desk.innerHTML = `<div class="desk-heading"><h2>${name}</h2><span class="badge ${tone}">${label}</span></div>
    <div class="metric">${metric}</div><p>${description}</p><dl class="rows">${rows.join('')}</dl>`;
}

function eventLabel(event) {
  const document = state.forecast.documents.find(({ id }) => id === event.condition)?.name;
  const asset = instrument[event.trade];
  const labels = {
    opened: 'Sessão iniciada com R$ 35 milhões de caixa próprio.',
    'closing-delay': `${document}: contraparte informa entrega às ${time(event.eta)}.`,
    'document-received': `${document}: evidência recebida.`,
    'closing-expedited': `Jurídico iniciou antecipação da escritura. Entrega prevista às ${time(event.due)}.`,
    'closing-released': 'Condições confirmadas e emissão liberada.',
    'closing-missed': 'Fechamento perdeu o horário de corte.',
    'instruction-mismatch': `${asset}: divergência na conta de custódia.`,
    'matching-repair-started': `Operações iniciou correção. Término previsto às ${time(event.due)}.`,
    'instruction-corrected': 'Conta de custódia corrigida.',
    'custody-authority-withdrawn': 'Custódia retirou a confirmação da instrução.',
    'instruction-repair-rejected': 'Correção interrompida por mudança na autorização.',
    'facility-unavailable': 'Contraparte retirou a disponibilidade da linha.',
    'funding-failed': 'A captação solicitada não foi creditada.',
    'agent-review': `${deskLabels[event.role]} · revisão necessária: ${reasons[event.reason]}.`,
    'agent-watch': `${deskLabels[event.role]} · monitorando: ${reasons[event.reason]}.`,
    'agent-rejected': `${deskLabels[event.role]} · ${reasons[event.reason]}.`,
    'agent-recovered': `${deskLabels[event.role]} · ${reasons[event.reason]}.`,
    'agent-degraded': `${deskLabels[event.role]} · ${reasons[event.reason]}. Operação automática suspensa nesta mesa até nova avaliação.`,
    matched: `${asset}: instrução conciliada.`,
    settled: `${asset}: DvP concluída · ${brl(event.amount)} · ${event.security}.`,
    'settlement-missed': `${asset}: falha no corte. ${event.cause}.`,
    'margin-update': `Contraparte informou nova chamada de margem de ${brl(event.amount)}.`,
    'funding-requested': `Tesouraria solicitou ${brl(event.amount)}, com chegada às ${time(event.due)}.`,
    'funding-arrived': `Recursos creditados ao IB: ${brl(event.amount)} líquidos, com custo de ${brl(event.fee)}.`,
    'margin-paid': `Chamada de margem paga: ${brl(event.amount)}.`,
    'margin-missed': `Chamada não paga no corte. Falta de ${brl(event.gap)}.`,
  };
  return labels[event.code] ?? event.code;
}

function draw() {
  const { scenario, policy, dayId, now, forecast: f, instructions, release, margin, funding, journal, outcomes, issuance, cutoff: deadline, end } = state;
  get('clock').textContent = time(now);
  get('day-name').textContent = `Dia ${dayId} · ${cases.find(({ id }) => id === scenario)?.name ?? ''} · ${policy === 'predictive' ? 'Preditiva' : 'Reativa'}`;
  for (const id of ['step', 'finish']) get(id).disabled = busy || now >= end;
  get('reset').disabled = busy;

  const closingStatus = release !== null
    ? (outcomes.closing ? ['good', 'Liberada'] : ['warn', 'Liberada em atraso'])
    : (f.closing > deadline.closing ? ['warn', 'Em risco'] : ['', 'Em andamento']);
  setDesk('closing', 'Mesa de emissão', closingStatus, time(f.closing),
    `${release === null ? 'Previsão de fechamento' : 'Fechamento efetivo'} · corte ${time(deadline.closing)}`, [
      row(issuance.issuer, issuance.id, `${formatNumber.format(issuance.units)} títulos · ${brl(issuance.units * issuance.priceCents)}`),
      ...f.documents.map((doc) =>
        row(doc.name, doc.received === null ? `Prev. ${time(doc.forecast)}` : time(doc.received), doc.provenance)),
    ]);

  const firmAtRisk = f.firm === null || f.firm > deadline.firm || now >= deadline.firm && !outcomes.firm;
  const primaryAtRisk = f.primary === null || f.primary > deadline.primary || now >= deadline.primary && !outcomes.primary;
  const settlementStatus = firmAtRisk || primaryAtRisk ? ['warn', 'Em risco ou falha'] :
    (outcomes.firm && outcomes.primary ? ['good', 'Liquidada'] : ['', 'Monitorando']);
  const done = Object.values(instructions).filter(({ settled }) => settled !== null).length;
  setDesk('settlement', 'Operações de títulos', settlementStatus,
    `${done} de 2`, 'Instruções com caixa e títulos liquidados', Object.entries(instructions).map(([id, entry]) => {
      const status = entry.settled !== null ? `DvP ${time(entry.settled)}` :
        now >= deadline[id] ? 'Falhou no corte' : entry.differences.length ? 'Divergência' : entry.matched ? 'Conciliada' : 'Pendente';
      const schedule = `Prev. ${time(f[id])} · corte ${time(deadline[id])}`;
      return row(instrument[id], status, entry.differences.includes('custody')
        ? `Conta ${entry.delivered.custody} ≠ ${entry.received.custody} · ${schedule}` : schedule);
    }));

  const treasuryStatus = margin.paid !== null ? (outcomes.margin ? ['good', 'Margem paga'] : ['warn', 'Paga em atraso']) :
    (f.gap > 0 ? ['warn', now >= deadline.margin ? 'Corte perdido' : 'Déficit previsto'] : ['', 'Coberta na projeção']);
  setDesk('treasury', 'Tesouraria do IB', treasuryStatus, brl(f.cash), 'Caixa próprio disponível agora', [
    row('Chamada de margem', brl(margin.amount), `Corte às ${time(deadline.margin)}`),
    row('Recebimento DvP esperado', brl(f.receipt), 'Condicionado à liquidação da posição própria'),
    row('Déficit previsto', brl(f.gap), `Sem o recebimento esperado: ${brl(Math.max(0, f.margin - f.cashWithoutTrade))}`),
    row('Linha de contingência', funding ? brl(funding.net) : brl(f.facility.maximum),
      funding ? `${funding.arrived ? 'Creditada' : funding.failed ? 'Não creditada' : 'Prevista'} às ${time(funding.at)} · custo ${brl(funding.fee)} · principal ${brl(funding.draw)}` :
        `Disponível em ${f.facility.minutes} min · última solicitação útil ${time(f.latest)}`),
  ]);

  get('event-count').textContent = `${state.events.length} ${state.events.length === 1 ? 'evento' : 'eventos'}`;
  get('opportunities').innerHTML = state.actions.length ?
    state.actions.map((action) => `<div class="action"><div>${action.cause}
      <small>Conclusão prevista às ${time(action.completion)} · corte ${time(action.deadline)}${action.id === 'funding' ? ` · ${brl(f.draw)} · déficit residual ${brl(f.residual)}` : ''}</small></div>
      <button data-action="${action.id}"${busy ? ' disabled' : ''}>${actionNames[action.id]}</button></div>`).join('') :
    '<p>Nenhuma ação disponível neste momento.</p>';
  get('timeline').innerHTML = [...state.events].reverse().map((event) => {
    const decision = event.decision;
    const source = decision?.signalId ? ` · evento ${decision.signalId} às ${time(decision.signalAt)}` : '';
    const residual = decision?.residual > 0 ? ` · déficit residual ${brl(decision.residual)}` : '';
    const trace = decision ? `<small>${deskLabels[decision.role]} · ${reasons[decision.reason]}${source}${residual}</small>` : '';
    return `<li><time>${time(event.at)}</time><div>${eventLabel(event)}${trace}</div></li>`;
  }).join('');
  get('ledger').innerHTML = journal.length ? `<dl class="rows">${journal.flatMap(({ at, legs }) =>
    legs.map(({ asset, from, to, amount }) => row(`${account[from]} → ${account[to]}`,
      asset === 'cash' ? brl(amount) : `${formatNumber.format(amount)} un.`, `${time(at)} · ${asset === 'cash' ? 'Caixa' : asset}`))).join('')}</dl>
    <small>${outcomes.reconciled ? 'Saldos reconciliados com os lançamentos.' : 'Divergência na reconciliação.'}</small>` :
    '<p>Nenhum lançamento até agora.</p>';
}

async function command(input) {
  if (busy || !state) return;
  busy = true;
  draw();
  fail();
  try {
    state = await api('/api/day', { ...input, dayId: state.dayId, version: state.version });
  } catch (error) {
    fail(error.message);
    if (error.status === 409) {
      try { state = await api('/api/day'); } catch (refreshError) { fail(refreshError.message); }
    }
  } finally {
    busy = false;
    draw();
  }
}

get('step').addEventListener('click', () => command({ type: 'advance', minutes: 15, automatic: false }));
get('finish').addEventListener('click', () => command({ type: 'advance', minutes: state.end - state.now, automatic: true }));
get('reset').addEventListener('click', () => command({ type: 'reset', scenario: get('scenario').value, policy: get('policy').value }));
get('opportunities').addEventListener('click', (event) => {
  const button = event.target.closest('[data-action]');
  if (button) command({ type: 'act', id: button.dataset.action });
});
get('compare').addEventListener('click', async () => {
  const button = get('compare');
  button.disabled = true;
  fail();
  try {
    const comparisons = await api('/api/benchmark');
    const summary = (day) => `<td>${day.closing ? time(day.closingAt) : 'Perdeu corte'}</td>
      <td>${day.primary ? time(day.primaryAt) : 'Falhou'}</td><td>${day.firm ? time(day.firmAt) : 'Falhou'}</td>
      <td>${day.margin ? time(day.marginAt) : 'Perdeu corte'}</td><td>${brl(day.cost)}</td>`;
    get('results').innerHTML = comparisons.map(({ name, reactive, predictive }) => `<section class="case"><h3>${name}</h3>
      <table><thead><tr><th scope="col">Política</th><th scope="col">Fechamento</th><th scope="col">DvP emissão</th>
      <th scope="col">DvP IB</th><th scope="col">Margem</th><th scope="col">Custo</th></tr></thead><tbody>
      <tr><th scope="row">Reativa</th>${summary(reactive)}</tr><tr><th scope="row">Preditiva</th>${summary(predictive)}</tr>
      </tbody></table><small>Ações preditivas: ${predictive.actions.map((action) =>
        `${time(action.at)} ${deskLabels[action.decision.role]}: ${benchmarkActions[action.code](action)}`).join(' · ') || 'nenhuma'}.
        ${reactive.reconciled && predictive.reconciled ? 'Saldos reconciliados nas duas políticas.' : 'Divergência no razão.'}</small></section>`).join('');
  } catch (error) {
    fail(error.message);
  } finally {
    button.disabled = false;
  }
});

for (const control of document.querySelectorAll('[data-control]')) control.disabled = true;
try {
  [state, cases] = await Promise.all([api('/api/day'), api('/api/scenarios')]);
  get('scenario').replaceChildren(...cases.map(({ name, id }) => new Option(name, id)));
  get('scenario').value = state.scenario;
  get('policy').value = state.policy;
  draw();
} catch (error) {
  fail(error.message);
}
