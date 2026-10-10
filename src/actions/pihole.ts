import type { DnsAdapter, Rule } from "./types";

interface PiholeOptions {
  base_url: string;
  password: () => string;
  domain: string;
  group_id: number;
  fetcher?: (url: string, init?: RequestInit) => Promise<Response>;
}
/** Dedicated lab only. The local executor holds credentials; no URL session tokens. */
export class PiholeAdapter implements DnsAdapter {
  #sid: string | null = null;
  #base: string;
  #fetch: (url: string, init?: RequestInit) => Promise<Response>;
  constructor(private readonly options: PiholeOptions) {
    const url = new URL(options.base_url);
    if (!['127.0.0.1', '[::1]'].includes(url.hostname) || !['http:', 'https:'].includes(url.protocol) ||
      url.pathname.replace(/\/$/, '') !== '/api' || url.username || url.password || url.search || url.hash ||
      !Number.isSafeInteger(options.group_id) || options.group_id < 1 ||
      !/^(?:[a-z0-9-]+\.)+[a-z]{2,}$/.test(options.domain)) throw new Error("Explicit loopback lab API and dedicated group required");
    this.#base = url.href.replace(/\/$/, '');
    this.#fetch = options.fetcher ?? fetch;
  }
  private scope(domain: string) {
    if (domain !== this.options.domain) throw new Error("Domain outside adapter capability");
  }
  private async request(path: string, method: string, body?: unknown, auth = true): Promise<any> {
    try {
      if (auth && !this.#sid) {
        const session = await this.request('/auth', 'POST', { password: this.options.password() }, false);
        if (session?.session?.valid !== true || typeof session.session.sid !== 'string' || !session.session.sid) throw new Error();
        this.#sid = session.session.sid;
      }
      const headers = new Headers({ 'Content-Type': 'application/json' });
      if (auth) headers.set('X-FTL-SID', this.#sid!);
      const response = await this.#fetch(this.#base + path, { method, headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        redirect: 'error', signal: AbortSignal.timeout(5_000) });
      if (!response.ok) { if (response.status === 401) this.#sid = null; throw new Error(); }
      if (response.status === 204) return null;
      const data = await response.json();
      if (!data || typeof data !== 'object' || data.error) throw new Error();
      return data;
    } catch { throw new Error('Pi-hole request failed; outcome may be unknown'); }
  }
  async read(domain: string): Promise<Rule | null> {
    this.scope(domain);
    // Query the typed list: an HTTP 404 alone is not proof that a rule is absent.
    const data = await this.request('/domains/deny/exact', 'GET');
    if (!Array.isArray(data.domains)) throw new Error('Invalid Pi-hole rule list');
    const found = data.domains.filter((row: any) => row.domain === domain);
    if (!found.length) return null;
    if (found.length !== 1) throw new Error('Ambiguous Pi-hole rule identity');
    const r = found[0];
    if (!Array.isArray(r.groups) || !r.groups.every(Number.isSafeInteger) || typeof r.enabled !== 'boolean' ||
      !(r.comment === null || typeof r.comment === 'string')) throw new Error('Invalid Pi-hole rule');
    return { domain, groups: r.groups, enabled: r.enabled, comment: r.comment ?? '' };
  }
  async create(rule: Rule): Promise<void> {
    this.scope(rule.domain);
    if (rule.groups.length !== 1 || rule.groups[0] !== this.options.group_id || !rule.enabled ||
      !/^router-guard:[a-f0-9]{64}$/.test(rule.comment)) throw new Error('Rule outside adapter capability');
    const data = await this.request('/domains/deny/exact', 'POST', rule);
    if (!Array.isArray(data?.processed?.errors) || data.processed.errors.length ||
      !Array.isArray(data?.processed?.success) || data.processed.success.length !== 1 ||
      data.processed.success[0].item !== rule.domain) throw new Error('Pi-hole rejected exact rule');
  }
  async remove(domain: string): Promise<void> {
    this.scope(domain);
    await this.request('/domains/deny/exact/' + encodeURIComponent(domain), 'DELETE');
  }
  async close(): Promise<void> {
    if (this.#sid) { try { await this.request('/auth', 'DELETE'); } finally { this.#sid = null; } }
  }
}
