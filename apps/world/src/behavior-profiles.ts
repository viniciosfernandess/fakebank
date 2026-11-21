import type { DatabaseSync } from "node:sqlite";

export interface PaymentBehaviorEvent {
  id: number;
  twin_ts: string;
  trace_id: string;
  user_id: string | null;
  device_id: string | null;
  geo: string | null;
  counterparty: string | null;
  amount_cents: number | null;
}

export interface BehaviorSignal {
  customerId: string;
  observed: Record<string, number | string>;
}

export const BEHAVIOR_POLICY_V1 = Object.freeze({
  version: 1,
  minimumCustomerSamples: 20,
  minimumDeviceSamples: 5,
  minimumAmountCents: 100_000,
  amountMultiple: 4,
  alertScore: 4,
});

const brtHour = new Intl.DateTimeFormat("en-US", {
  timeZone: "America/Sao_Paulo", hour: "2-digit", hourCycle: "h23",
});

/** The caller owns the transaction and advances its telemetry cursor with these writes. */
export class BehaviorProfiles {
  private readonly db: DatabaseSync;

  constructor(db: DatabaseSync) {
    this.db = db;
    db.exec(`CREATE TABLE IF NOT EXISTS sentinel_behavior_customers (
      customer_id TEXT PRIMARY KEY, sample_count INTEGER NOT NULL CHECK(sample_count>0),
      amount_sum_cents INTEGER NOT NULL CHECK(amount_sum_cents>0),
      last_event_id INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sentinel_behavior_devices (
      customer_id TEXT NOT NULL, device_id TEXT NOT NULL,
      sample_count INTEGER NOT NULL CHECK(sample_count>0),
      first_geo TEXT, last_event_id INTEGER NOT NULL,
      PRIMARY KEY(customer_id,device_id)
    );
    CREATE TABLE IF NOT EXISTS sentinel_behavior_recipients (
      customer_id TEXT NOT NULL, recipient_id TEXT NOT NULL,
      sample_count INTEGER NOT NULL CHECK(sample_count>0),
      amount_sum_cents INTEGER NOT NULL CHECK(amount_sum_cents>0),
      last_event_id INTEGER NOT NULL,
      PRIMARY KEY(customer_id,recipient_id)
    );
    CREATE TABLE IF NOT EXISTS sentinel_behavior_hours (
      customer_id TEXT NOT NULL, hour_brt INTEGER NOT NULL CHECK(hour_brt BETWEEN 0 AND 23),
      sample_count INTEGER NOT NULL CHECK(sample_count>0),
      PRIMARY KEY(customer_id,hour_brt)
    );`);
  }

  observe(event: PaymentBehaviorEvent): BehaviorSignal | undefined {
    const { id, user_id: customerId, device_id: deviceId, geo,
      counterparty: recipientId, amount_cents: amountCents } = event;
    const timestamp = Date.parse(event.twin_ts);
    if (!Number.isSafeInteger(id) || id <= 0 ||
      !customerId || !/^cus_[A-Za-z0-9_-]{1,96}$/.test(customerId) ||
      !recipientId || !/^[A-Za-z][A-Za-z0-9_-]{1,127}$/.test(recipientId) ||
      !Number.isSafeInteger(amountCents) || amountCents === null || amountCents <= 0 ||
      !Number.isFinite(timestamp)) return undefined;

    const hour = Number(brtHour.format(new Date(timestamp)));
    const customer = this.db.prepare(`SELECT sample_count,amount_sum_cents
      FROM sentinel_behavior_customers WHERE customer_id=?`).get(customerId) as
      { sample_count: number; amount_sum_cents: number } | undefined;
    const recipient = this.db.prepare(`SELECT sample_count,amount_sum_cents
      FROM sentinel_behavior_recipients WHERE customer_id=? AND recipient_id=?`)
      .get(customerId, recipientId) as
      { sample_count: number; amount_sum_cents: number } | undefined;
    const hourSample = this.db.prepare(`SELECT sample_count FROM sentinel_behavior_hours
      WHERE customer_id=? AND hour_brt=?`).get(customerId, hour) as
      { sample_count: number } | undefined;
    const device = deviceId ? this.db.prepare(`SELECT sample_count,first_geo
      FROM sentinel_behavior_devices WHERE customer_id=? AND device_id=?`)
      .get(customerId, deviceId) as { sample_count: number; first_geo: string | null } | undefined : undefined;

    const customerSamples = customer?.sample_count ?? 0;
    const typicalAmount = customer ? Math.floor(customer.amount_sum_cents / customer.sample_count) : 0;
    const amountAnomaly = customerSamples >= BEHAVIOR_POLICY_V1.minimumCustomerSamples &&
      amountCents >= Math.max(BEHAVIOR_POLICY_V1.minimumAmountCents,
        BEHAVIOR_POLICY_V1.amountMultiple * typicalAmount);
    const newRecipient = recipient === undefined;
    const quietHour = (hourSample?.sample_count ?? 0) <= 1;
    const newGeo = !!(geo && device?.first_geo && geo !== device.first_geo &&
      device.sample_count >= BEHAVIOR_POLICY_V1.minimumDeviceSamples);
    const score = Number(amountAnomaly) * 2 + Number(newRecipient) +
      Number(quietHour) + Number(newGeo);

    this.db.prepare(`INSERT INTO sentinel_behavior_customers VALUES (?,?,?,?)
      ON CONFLICT(customer_id) DO UPDATE SET
      sample_count=sample_count+1,amount_sum_cents=amount_sum_cents+excluded.amount_sum_cents,
      last_event_id=excluded.last_event_id`).run(customerId, 1, amountCents, id);
    this.db.prepare(`INSERT INTO sentinel_behavior_recipients VALUES (?,?,?,?,?)
      ON CONFLICT(customer_id,recipient_id) DO UPDATE SET
      sample_count=sample_count+1,amount_sum_cents=amount_sum_cents+excluded.amount_sum_cents,
      last_event_id=excluded.last_event_id`).run(customerId, recipientId, 1, amountCents, id);
    this.db.prepare(`INSERT INTO sentinel_behavior_hours VALUES (?,?,1)
      ON CONFLICT(customer_id,hour_brt) DO UPDATE SET sample_count=sample_count+1`)
      .run(customerId, hour);
    if (deviceId && /^[A-Za-z][A-Za-z0-9_-]{1,127}$/.test(deviceId))
      this.db.prepare(`INSERT INTO sentinel_behavior_devices VALUES (?,?,?,?,?)
        ON CONFLICT(customer_id,device_id) DO UPDATE SET
        sample_count=sample_count+1,
        first_geo=COALESCE(first_geo,excluded.first_geo),
        last_event_id=excluded.last_event_id`).run(customerId, deviceId, 1, geo, id);

    if (!amountAnomaly || score < BEHAVIOR_POLICY_V1.alertScore) return undefined;
    return { customerId, observed: {
      policy_version: BEHAVIOR_POLICY_V1.version,
      event_id: id, trace_id: event.trace_id,
      amount_cents: amountCents, typical_amount_cents: typicalAmount,
      customer_samples: customerSamples,
      recipient_samples: recipient?.sample_count ?? 0,
      recipient_typical_cents: recipient ? Math.floor(recipient.amount_sum_cents / recipient.sample_count) : 0,
      hour_brt: hour, hour_samples: hourSample?.sample_count ?? 0,
      device_samples: device?.sample_count ?? 0,
      geo_changed: Number(newGeo), score,
    } };
  }
}
