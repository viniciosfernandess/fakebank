export const PRECONDITIONS = [
  "precond.auth.none", "precond.session.valid_low_priv", "precond.session.valid_high_balance",
  "precond.account.new_under_24h", "precond.account.multi_owned", "precond.device.new",
  "precond.channel.support", "precond.channel.api_client", "precond.channel.app",
  "precond.limit.near_threshold", "precond.limit.changed_recently", "precond.clock.scheduled_future",
  "precond.clock.window_boundary", "precond.concurrency.parallel", "precond.retry.repeated_request",
  "precond.id.client_supplied", "precond.id.sequential", "precond.field.server_controlled_exposed",
  "precond.state.step_skippable", "precond.state.pending_review", "precond.state.cancelled_or_reversed",
  "precond.value.fractional", "precond.value.boundary_or_negative", "precond.counterparty.new_payee",
  "precond.counterparty.mule_network", "precond.feature.flag_on", "precond.route.deprecated",
  "precond.token.expired_or_scoped", "precond.error.verbose", "precond.rate.unbounded",
] as const;
const known = new Set<string>(PRECONDITIONS);
export function validatePreconditions(values: readonly string[]): string[] {
  const other = values.filter((value) => value.startsWith("precond.other:"));
  if (other.length > 1 || other.some((value) => !/^precond\.other:[a-z0-9_]{1,32}$/.test(value)) ||
    values.some((value) => !known.has(value) && !value.startsWith("precond.other:")))
    throw new Error("PRECONDITION_UNKNOWN");
  return [...new Set(values)].sort();
}
