import { inspectPixOutcome, planPixPolicy } from "./pix-outcome-review.mjs";

let input = "";
for await (const chunk of process.stdin) input += chunk;
const payload = JSON.parse(input);
switch (process.argv[2]) {
  case "architect":
    console.log(JSON.stringify(planPixPolicy(payload.report, payload.key, payload.memory, payload.tried)));
    break;
  case "guard":
    console.log(JSON.stringify(inspectPixOutcome(payload.trial, payload.expectedPhases, payload.guardOptions)));
    break;
  default:
    throw new Error("PIX_OUTCOME_ROLE_INVALID");
}
