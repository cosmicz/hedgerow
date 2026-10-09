// Sponsor endpoint boundary. ClickHouse and MongoDB hold Router Guard data and
// must stay on this machine: only literal loopback addresses, the expected
// scheme, an explicit port, a single host and no credentials or options are
// accepted. Validation happens before any client exists, so an invalid
// endpoint is never contacted. Reasons never echo the raw string, which may
// contain credentials.

export type EndpointCheck =
  | { readonly ok: true; readonly url: string }
  | { readonly ok: false; readonly reason: string };

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "[::1]"]);

export function checkClickHouseEndpoint(raw: string): EndpointCheck {
  return check(raw, "http:", (url) => (url.pathname === "/" ? null : "path not allowed"));
}

export function checkMongoEndpoint(raw: string): EndpointCheck {
  if (typeof raw !== "string" || !raw.startsWith("mongodb://")) {
    return { ok: false, reason: "invalid endpoint: scheme must be mongodb:// (no +srv)" };
  }
  const authority = raw.slice("mongodb://".length).split(/[/?#]/, 1)[0] ?? "";
  if (authority.includes(",")) {
    return { ok: false, reason: "invalid endpoint: exactly one host required" };
  }
  // WHATWG URL does not parse mongodb://; the same rules apply on an http view of it.
  const verdict = check(`http://${raw.slice("mongodb://".length)}`, "http:", (url) =>
    url.pathname === "/" || url.pathname === "" ? null : "database belongs in config.database, not the URI");
  return verdict.ok ? { ok: true, url: raw } : verdict;
}

function check(raw: string, scheme: string, extra: (url: URL) => string | null): EndpointCheck {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return { ok: false, reason: "invalid endpoint: not a URL" };
  }
  const problem =
    url.protocol !== scheme ? `scheme must be ${scheme}` :
    url.username || url.password ? "credentials not allowed" :
    !LOOPBACK_HOSTS.has(url.hostname) ? "host must be 127.0.0.1 or [::1]" :
    url.port === "" ? "explicit port required" :
    url.search || url.hash ? "query options and fragments not allowed" :
    extra(url);
  return problem ? { ok: false, reason: `invalid endpoint: ${problem}` } : { ok: true, url: raw };
}
