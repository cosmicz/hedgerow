// In-memory stand-in for the isolated Pi-hole lab, used by the sponsor proof.
// It implements the action core's DnsAdapter and verifier contracts, so the
// real ActionService drives it; every lookup it answers becomes a synthetic
// dns_query observation. Nothing here is VM-live or physical evidence, and the
// mode on every record says so.
import type { DnsAdapter, Proposal, Rule, Verification } from "../../actions/types.js";
import type { Observation } from "./types.js";

/** Deterministic clock: every read advances one second, so artifacts are reproducible. */
export class SyntheticClock {
  #t: number;

  constructor(start: number) {
    this.#t = start;
  }

  now(): number {
    this.#t += 1_000;
    return this.#t;
  }
}

export interface RuleWindow {
  readonly domain: string;
  readonly created_at: number;
  removed_at: number | null;
}

export interface SyntheticLabOptions {
  readonly network_scope: string;
  readonly clock: SyntheticClock;
  /** Owned lab client used by the verifier (RFC 5737 documentation address). */
  readonly probe_client: string;
  readonly benign_domain: string;
}

export class SyntheticLab {
  readonly ruleWindows: RuleWindow[] = [];
  creates = 0;
  readonly #options: SyntheticLabOptions;
  readonly #rules = new Map<string, Rule>();
  #pending: Observation[] = [];
  #seq = 0;

  constructor(options: SyntheticLabOptions) {
    this.#options = options;
  }

  readonly adapter: DnsAdapter = {
    read: async (domain) => {
      const rule = this.#rules.get(domain);
      return rule ? structuredClone(rule) : null;
    },
    create: async (rule) => {
      this.creates += 1;
      this.#rules.set(rule.domain, structuredClone(rule));
      this.ruleWindows.push({ domain: rule.domain, created_at: this.#options.clock.now(), removed_at: null });
    },
    remove: async (domain) => {
      this.#rules.delete(domain);
      const open = this.ruleWindows.filter((window) => window.domain === domain && window.removed_at === null).at(-1);
      if (open) {
        open.removed_at = this.#options.clock.now();
      }
    },
  };

  /** Independent check from the probe client: resolves target and benign names through the lab resolver. */
  readonly verify = async (proposal: Proposal): Promise<Verification> => {
    const target = this.lookup(proposal.domain, this.#options.probe_client);
    const benign = this.lookup(this.#options.benign_domain, this.#options.probe_client);
    return {
      target: target === "blocked" ? "blocked" : "resolved",
      benign: benign === "answered" ? "resolved" : "failed",
      checked_at: this.#options.clock.now(),
      mode: "synthetic",
    };
  };

  lookup(domain: string, client: string): "answered" | "blocked" {
    const rule = this.#rules.get(domain);
    const status = rule?.enabled ? "blocked" : "answered";
    const seq = ++this.#seq;
    const observedAt = new Date(this.#options.clock.now()).toISOString();
    this.#pending.push({
      id: `observation:synthetic-${seq}`,
      evidence_revision: `synthetic:${this.#options.network_scope}`,
      observed_at: observedAt,
      received_at: observedAt,
      source_id: "synthetic-resolver",
      network_scope: this.#options.network_scope,
      kind: "dns_query",
      evidence_ref: `synthetic://resolver/${seq}`,
      mode: "synthetic",
      freshness: "fresh",
      payload: { domain, client, status },
    });
    return status;
  }

  hasRule(domain: string): boolean {
    return this.#rules.has(domain);
  }

  /** Observations produced since the last drain, oldest first. */
  drain(): Observation[] {
    const drained = this.#pending;
    this.#pending = [];
    return drained;
  }
}
