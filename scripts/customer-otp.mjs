import { createConnection } from "node:net";
import { resolve, join } from "node:path";
import { customerOtpMailboxDirectory } from "../apps/server/src/customer-otp-path.ts";

const [cpf, challengeId] = process.argv.slice(2);
if (!cpf || !/^\d{11}$/.test(cpf) ||
  !challengeId || !/^[A-Za-z0-9_-]{1,128}$/.test(challengeId)) {
  process.stderr.write("Usage: pnpm customer:otp <fictitious-cpf> <challenge-id>\n");
  process.exitCode = 2;
} else {
  const path = join(customerOtpMailboxDirectory(resolve(process.env.DATA_DIR || "data")),
    "mailbox.sock");
  const socket = createConnection(path);
  socket.setTimeout(3000, () => socket.destroy(new Error("OTP mailbox timeout")));
  let result = "";
  socket.on("connect", () => socket.write(JSON.stringify({ cpf,
    challenge_id: challengeId }) + "\n"));
  socket.on("data", (chunk) => { result += chunk.toString("utf8"); });
  socket.on("end", () => {
    const match = /^OTP (\d{6})\n$/.exec(result);
    if (match) process.stdout.write(`${match[1]}\n`);
    else { process.stderr.write("OTP unavailable or expired. Request a new login code.\n");
      process.exitCode = 1; }
  });
  socket.on("error", () => { process.stderr.write("Local OTP mailbox unavailable.\n");
    process.exitCode = 1; });
}
