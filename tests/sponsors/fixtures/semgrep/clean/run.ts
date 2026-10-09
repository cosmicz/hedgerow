// Must not fire: fixed argv without shell lives only in the allowlisted scanner.
export function describeLookup(base: string, domain: string) {
  const url = new URL("/api/queries", base);
  url.searchParams.set("domain", domain);
  console.log("lookup requested for", domain);
  return url;
}
