import type { Area } from "../../../packages/contracts/src/index.ts";
import type { Bank } from "../../world/src/bank.ts";
import { expectedAreaRate } from "../../world/src/simulator.ts";

export interface HonestProfile { area: Area; typical_amount_brl_p50: number;
  typical_rate_per_min: number; notes: string; sample_size: number; }
export function honestProfile(bank: Bank, area: Area): HonestProfile {
  let medianCents = 0;
  let sampleSize = 0;
  if (area === "pix") {
    sampleSize = (bank.db.prepare(`SELECT COUNT(*) n FROM pix_transfers p
      JOIN accounts a ON a.id=p.from_account JOIN customers c ON c.id=a.customer_id
      WHERE p.status='settled' AND c.is_attacker_owned=0`).get() as { n: number }).n;
    if (sampleSize) medianCents = (bank.db.prepare(`SELECT p.amount FROM pix_transfers p
      JOIN accounts a ON a.id=p.from_account JOIN customers c ON c.id=a.customer_id
      WHERE p.status='settled' AND c.is_attacker_owned=0 ORDER BY p.amount LIMIT 1 OFFSET ?`)
      .get(Math.floor((sampleSize - 1) / 2)) as { amount: number }).amount;
  }
  const hasTicks = bank.db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='sim_ticks'").get();
  const observed = hasTicks ? bank.db.prepare(`SELECT AVG(COALESCE(json_extract(by_area_json,?),0)) rate
    FROM (SELECT by_area_json FROM sim_ticks ORDER BY minute DESC LIMIT 60)`)
    .get(`$.${area}`) as { rate: number | null } : undefined;
  return { area, typical_amount_brl_p50: medianCents / 100,
    typical_rate_per_min: observed?.rate ?? expectedAreaRate(area, bank.now()),
    notes: sampleSize ? "Median of honest settled Pix; rate from recent simulator ticks when available."
      : "No historical amount sample; rate uses the simulator's current BRT schedule.", sample_size: sampleSize };
}
