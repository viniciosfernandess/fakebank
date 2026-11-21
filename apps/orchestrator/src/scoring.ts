import type { Area } from "../../../packages/contracts/src/index.ts";

const clamp = (value: number): number => Math.max(0, Math.min(100, value));
const mean = (values: readonly number[]): number => values.length ?
  values.reduce((sum, value) => sum + value, 0) / values.length : 0;
export interface BreachScoreInput {
  moneyBrl: number;
  novelty: number;
  detectedAfterSeconds: number | null;
  reported: boolean;
}
export function redScore(breaches: readonly BreachScoreInput[]): number {
  if (!breaches.length) return 0;
  const money = breaches.reduce((sum, breach) => sum + breach.moneyBrl * (breach.reported ? 1 : 0.5), 0);
  const m = 100 * Math.min(1, Math.log10(1 + Math.max(0, money)) / Math.log10(100_001));
  const n = 100 * Math.min(1, breaches.reduce((sum, breach) => sum + (breach.reported ? breach.novelty : 0), 0) / 3);
  const d = 100 * mean(breaches.map((breach) => breach.detectedAfterSeconds === null ? 1 :
    Math.min(1, Math.max(0, breach.detectedAfterSeconds) / 600)));
  return clamp(0.45 * m + 0.35 * n + 0.20 * d);
}
export interface BlueIncidentScoreInput {
  detectedAfterSeconds: number | null;
  containedAfterAlertSeconds: number | null;
  mergedAfterEffectSeconds: number | null;
}
export interface BlueScoreInput {
  incidents: readonly BlueIncidentScoreInput[];
  restoredBrl: number;
  openAfterDeployBrl: number;
  blockedAttempts: number;
  totalAttempts: number;
  honestCustomersWronglyBlocked: number;
  reviewRejections: number;
  quarantinedAreas: number;
}
export function blueScore(input: BlueScoreInput): number {
  const incidents = input.incidents;
  const subscore = (value: number | null, max: number, fullAt: number): number =>
    value === null ? 0 : 100 * Math.max(0, Math.min(1, (max - value) / (max - fullAt)));
  const detection = incidents.length ? mean(incidents.map((item) => subscore(item.detectedAfterSeconds, 600, 90))) : 100;
  const containment = incidents.length ? mean(incidents.map((item) => subscore(item.containedAfterAlertSeconds, 600, 120))) : 100;
  const merge = incidents.length ? mean(incidents.map((item) => subscore(item.mergedAfterEffectSeconds, 1800, 600))) : 100;
  const recover = input.openAfterDeployBrl <= 0 ? 100 :
    100 * Math.min(1, Math.max(0, input.restoredBrl) / input.openAfterDeployBrl);
  const prevent = input.totalAttempts <= 0 ? 100 :
    100 * Math.min(1, Math.max(0, input.blockedAttempts) / input.totalAttempts);
  return clamp(0.15 * detection + 0.20 * containment + 0.20 * merge + 0.20 * recover +
    0.25 * prevent - Math.min(40, 5 * input.honestCustomersWronglyBlocked) -
    Math.min(15, 3 * input.reviewRejections) - 10 * input.quarantinedAreas);
}
export const AREA_WEIGHTS: Record<Area, number> = {
  ledger: 0.20, pix: 0.20, auth: 0.15, accounts: 0.15,
  cards: 0.10, loans: 0.10, api_gateway: 0.10,
};
export interface AreaHealthInput {
  openSeverityWeight: number;
  probationSeverityWeight: number;
  quarantined: boolean;
  wronglyBlockedLast24h: number;
  unrecoveredLossBrl: number;
  regressionTests: number;
}
export function areaHealth(input: AreaHealthInput): number {
  const vulnerability = input.openSeverityWeight + 0.25 * input.probationSeverityWeight;
  const falseBlocks = Math.min(20, 4 * input.wronglyBlockedLast24h);
  const loss = 15 * Math.min(1, input.unrecoveredLossBrl / 5000);
  const hardening = Math.min(3, 0.1 * input.regressionTests);
  return clamp(100 - vulnerability - (input.quarantined ? 25 : 0) - falseBlocks - loss + hardening);
}
export function overallHealth(areas: Record<Area, number>): number {
  const weighted = (Object.keys(AREA_WEIGHTS) as Area[]).reduce((sum, area) => sum + AREA_WEIGHTS[area] * areas[area], 0);
  return clamp(0.70 * weighted + 0.30 * Math.min(...Object.values(areas)));
}
