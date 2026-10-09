// Sponsor backends with a visible local fallback.
//
// Observation store: every write goes to the in-process store first and to
// ClickHouse best-effort. Reads come from ClickHouse only while it has
// received every write; after any ClickHouse failure it could be missing rows,
// so reads are served locally from then on and the status says why.
//
// Action projection: every revision MongoDB accepts is mirrored locally. On a
// MongoDB failure the local mirror takes over at the same revision, so later
// journal transitions keep projecting (non-durable, visibly degraded). Neither
// fallback grants or withholds action authority; the journal owns that.
import { LocalActionProjection, project } from "./local/action-projection.js";
import { LocalObservationStore } from "./local/observation-store.js";
import type {
  ActionProjection,
  ActionRecord,
  AuditEvent,
  DomainEvidence,
  EvidenceQuery,
  ObservationBackend,
  ObservationStore,
  ProjectedAction,
  PublishResult,
  Observation,
  SponsorStatus,
} from "./types.js";

export interface SourcedEvidence {
  readonly evidence: DomainEvidence;
  readonly backend: ObservationBackend;
  readonly latency_ms: number;
}

export class ResilientObservationStore implements ObservationStore {
  readonly #primary: ObservationStore | null;
  readonly #local = new LocalObservationStore();
  readonly #version: string | null;
  #primaryComplete: boolean;
  #failure: string | null;
  #lastLatency: number | null = null;

  /** primary is null when ClickHouse is not configured or unreachable at startup; reason says why. */
  constructor(primary: ObservationStore | null, version: string | null, reason: string | null = null) {
    this.#primary = primary;
    this.#version = version;
    this.#primaryComplete = primary !== null;
    this.#failure = primary ? null : (reason ?? "not configured");
  }

  get backend(): ObservationBackend {
    return this.#primaryComplete && this.#primary ? this.#primary.backend : "local";
  }

  async record(observations: readonly Observation[]): Promise<number> {
    const accepted = await this.#local.record(observations);
    await this.#mirror((primary) => primary.record(observations));
    return accepted;
  }

  async domainEvidence(query: EvidenceQuery): Promise<DomainEvidence> {
    return (await this.sourcedEvidence(query)).evidence;
  }

  async sourcedEvidence(query: EvidenceQuery): Promise<SourcedEvidence> {
    if (this.#primaryComplete && this.#primary) {
      const started = performance.now();
      try {
        const evidence = await this.#primary.domainEvidence(query);
        this.#lastLatency = Math.round(performance.now() - started);
        return { evidence, backend: this.#primary.backend, latency_ms: this.#lastLatency };
      } catch (error) {
        this.#degrade(error);
      }
    }
    const started = performance.now();
    const evidence = await this.#local.domainEvidence(query);
    return { evidence, backend: "local", latency_ms: Math.round(performance.now() - started) };
  }

  async appendAudit(event: AuditEvent): Promise<void> {
    await this.#local.appendAudit(event);
    await this.#mirror((primary) => primary.appendAudit(event));
  }

  async auditTrail(subject_id: string): Promise<readonly AuditEvent[]> {
    if (this.#primaryComplete && this.#primary) {
      try {
        return await this.#primary.auditTrail(subject_id);
      } catch (error) {
        this.#degrade(error);
      }
    }
    return this.#local.auditTrail(subject_id);
  }

  status(): SponsorStatus {
    return {
      sponsor: "clickhouse",
      health: this.#primaryComplete ? "ok" : this.#primary ? "degraded" : "unavailable",
      serving_backend: this.backend,
      version: this.#version,
      detail: this.#primaryComplete
        ? "Evidence and audit queries served by ClickHouse"
        : `ClickHouse ${this.#primary ? "failed" : "unavailable"} (${this.#failure}); serving in-process evidence for this session`,
      latency_ms: this.#lastLatency,
    };
  }

  async #mirror(write: (primary: ObservationStore) => Promise<unknown>): Promise<void> {
    if (!this.#primaryComplete || !this.#primary) {
      return;
    }
    try {
      await write(this.#primary);
    } catch (error) {
      this.#degrade(error);
    }
  }

  #degrade(error: unknown): void {
    this.#primaryComplete = false;
    this.#failure = (error as Error).message.slice(0, 200);
  }
}

export class ResilientActionProjection implements ActionProjection {
  readonly #primary: ActionProjection | null;
  readonly #local = new LocalActionProjection();
  readonly #version: string | null;
  #failure: string | null;
  #failedAt: string | null = null;

  /** primary is null when MongoDB was unreachable at startup; reason says why. */
  constructor(primary: ActionProjection | null, version: string | null, reason: string | null = null) {
    this.#primary = primary;
    this.#version = version;
    this.#failure = primary ? null : (reason ?? "not configured");
  }

  get backend(): ActionProjection["backend"] {
    return this.#usingPrimary() ? "mongodb" : "local";
  }

  get durable(): boolean {
    return this.#usingPrimary() && (this.#primary?.durable ?? false);
  }

  async publish(record: ActionRecord, expected_revision: number): Promise<PublishResult> {
    if (this.#usingPrimary()) {
      try {
        const result = await this.#primary!.publish(record, expected_revision);
        if (result.ok) {
          this.#local.mirror(project(record, result.revision));
        }
        return result;
      } catch (error) {
        this.#degrade(error);
      }
    }
    return this.#local.publish(record, expected_revision);
  }

  latest(digest: string): Promise<ProjectedAction | null> {
    return this.#read((projection) => projection.latest(digest));
  }

  history(digest: string): Promise<readonly ProjectedAction[]> {
    return this.#read((projection) => projection.history(digest));
  }

  inScope(network_scope: string): Promise<readonly ProjectedAction[]> {
    return this.#read((projection) => projection.inScope(network_scope));
  }

  status(): SponsorStatus {
    const ok = this.#usingPrimary();
    return {
      sponsor: "mongodb",
      health: ok ? "ok" : this.#primary ? "degraded" : "unavailable",
      serving_backend: this.backend,
      version: this.#version,
      detail: ok
        ? "Action projection durable in MongoDB"
        : `MongoDB ${this.#primary ? `failed at ${this.#failedAt}` : "unavailable"} (${this.#failure}); ` +
          "in-process projection continues this session, not durable",
      latency_ms: null,
    };
  }

  #usingPrimary(): boolean {
    return this.#failure === null && this.#primary !== null;
  }

  async #read<T>(operation: (projection: ActionProjection) => Promise<T>): Promise<T> {
    if (this.#usingPrimary()) {
      try {
        return await operation(this.#primary!);
      } catch (error) {
        this.#degrade(error);
      }
    }
    return operation(this.#local);
  }

  #degrade(error: unknown): void {
    this.#failure = (error as Error).message.slice(0, 200);
    this.#failedAt = new Date().toISOString();
  }
}
