// Must fire: rg-secret-in-url-or-log (x2), rg-tls-verification-disabled (x1)
export function leak(base: string, sid: string) {
  const url = `${base}/api/stats?sid=${sid}`;
  console.log("pihole session", sid);
  return fetch(url, { tls: { rejectUnauthorized: false } } as RequestInit);
}
