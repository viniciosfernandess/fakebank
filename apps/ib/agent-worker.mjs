const role = process.argv[2];

function closing({ required, eta, registration, projected, completion, cutoff, primaryCutoff, now }) {
  if (!required || projected <= cutoff) return { kind: 'observe' };
  const release = completion + registration;
  if (completion < eta && release <= primaryCutoff) {
    return { kind: 'propose', action: 'closing', completion, deadline: cutoff,
      code: release <= cutoff ? 'closing-preserved' : 'primary-protected' };
  }
  return { kind: 'review', code: now >= cutoff ? 'closing-cutoff-missed' : 'closing-unrecoverable' };
}

function settlement({ settled, mismatches, authorized, pending, readyAt, repairMinutes, cutoff, now }) {
  if (settled || !mismatches.length) return { kind: 'observe' };
  if (!authorized || mismatches.length !== 1 || mismatches[0] !== 'custody') {
    return { kind: 'review', code: 'instruction-not-authorized' };
  }
  if (pending) return { kind: 'observe' };
  const completion = now + repairMinutes;
  if (Math.max(readyAt, completion) > cutoff) return { kind: 'review', code: 'settlement-unrecoverable' };
  return { kind: 'propose', action: 'matching', completion, deadline: cutoff, code: 'settlement-preserved' };
}

function treasury({ currentGap, stressGap, available, pending, failed, canWaitForRepair, now, latest, marginCutoff,
  feeBps, lead }) {
  if (!currentGap) {
    return stressGap && now < latest ? { kind: 'watch', code: 'conditional-receipt' } : { kind: 'observe' };
  }
  if (pending || failed) return { kind: 'review', code: 'funding-already-committed' };
  if (canWaitForRepair && now < latest) return { kind: 'watch', code: 'repair-before-funding' };
  if (now > latest) return { kind: 'review', code: 'funding-window-closed' };
  if (!available) return { kind: 'review', code: 'facility-unavailable' };
  const draw = Math.min(available, Math.ceil(currentGap * 10_000 / (10_000 - feeBps)));
  const fee = Math.ceil(draw * feeBps / 10_000);
  return { kind: 'propose', action: 'funding', completion: now + lead, deadline: marginCutoff,
    draw, fee, residual: Math.max(0, currentGap - draw + fee), code: 'funding-sized' };
}

const evaluate = { closing, settlement, treasury }[role];
if (!evaluate || typeof process.send !== 'function') throw new Error('Worker requires a known IPC role.');
process.on('disconnect', () => process.exit(0));
process.on('message', ({ job, revision, facts }) => {
  process.send({ job, revision, role, ...evaluate(facts) });
});
