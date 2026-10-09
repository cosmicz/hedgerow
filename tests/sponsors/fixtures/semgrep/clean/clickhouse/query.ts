// Must not fire: typed parameter, no interpolation.
export const EVIDENCE_SQL = "SELECT count() FROM router_guard.dns_lookups WHERE domain = {domain:String}";
export const label = (n: number) => `${n} rows`;
