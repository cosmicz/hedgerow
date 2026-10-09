// Must fire: rg-clickhouse-interpolated-sql
export function evidenceSql(domain: string) {
  return `SELECT count() FROM router_guard.dns_lookups WHERE domain = '${domain}'`;
}
