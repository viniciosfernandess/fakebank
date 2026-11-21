import { createHmac, randomBytes, randomInt, timingSafeEqual } from "node:crypto";
import { Bank } from "../bank.ts";

function luhnDigit(prefix: string): string {
  let sum = 0;
  for (let index = prefix.length - 1, position = 0; index >= 0; index--, position++) {
    let digit = Number(prefix[index]);
    if (position % 2 === 0) { digit *= 2; if (digit > 9) digit -= 9; }
    sum += digit;
  }
  return String((10 - sum % 10) % 10);
}

export class CardVault {
  readonly bank: Bank;
  constructor(bank: Bank) {
    this.bank = bank;
    bank.db.exec(`CREATE TABLE IF NOT EXISTS card_vault (
      card_id TEXT PRIMARY KEY REFERENCES cards(id),
      pan TEXT NOT NULL UNIQUE CHECK(length(pan)=16),
      cvv_secret TEXT NOT NULL,
      last4 TEXT NOT NULL CHECK(length(last4)=4)
    );`);
    const rows = bank.db.prepare(`SELECT id FROM cards WHERE id NOT IN
      (SELECT card_id FROM card_vault)`).all() as { id: string }[];
    for (const row of rows) this.ensureCard(row.id);
  }

  ensureCard(cardId: string): void {
    if (this.bank.db.prepare("SELECT 1 FROM card_vault WHERE card_id=?").get(cardId)) return;
    const prefix = `402912${String(randomInt(0, 1_000_000_000)).padStart(9, "0")}`;
    const pan = prefix + luhnDigit(prefix);
    this.bank.db.prepare(`INSERT INTO card_vault (card_id,pan,cvv_secret,last4)
      VALUES (?,?,?,?)`).run(cardId, pan, randomBytes(32).toString("hex"), pan.slice(-4));
  }

  last4(cardId: string): string {
    this.ensureCard(cardId);
    return (this.bank.db.prepare("SELECT last4 FROM card_vault WHERE card_id=?")
      .get(cardId) as { last4: string }).last4;
  }

  currentCvv(cardId: string): string {
    this.ensureCard(cardId);
    const row = this.bank.db.prepare(`SELECT v.cvv_secret,c.kind FROM card_vault v
      JOIN cards c ON c.id=v.card_id WHERE v.card_id=?`).get(cardId) as
      { cvv_secret: string; kind: string };
    const window = row.kind === "virtual" ? Math.floor(this.bank.now().getTime() / 900_000) : 0;
    const digest = createHmac("sha256", Buffer.from(row.cvv_secret, "hex"))
      .update(`${cardId}:${window}`).digest();
    return String(digest.readUInt32BE(0) % 1000).padStart(3, "0");
  }

  verifyCvv(cardId: string, cvv: string): boolean {
    if (!/^\d{3}$/.test(cvv)) return false;
    const expected = Buffer.from(this.currentCvv(cardId));
    return timingSafeEqual(Buffer.from(cvv), expected);
  }
}
