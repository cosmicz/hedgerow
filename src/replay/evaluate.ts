import { createHash } from "node:crypto";

import type { Coverage, Finding, FindingState } from "../domain/finding.js";
import type { Observation, ObservationMode } from "../domain/observation.js";
import { normalizeFixture, type ExpectedCollector, type ReplayContext, validateReplayContext } from "./normalize.js";

export interface ReplayResult {
  readonly observations: readonly Observation[];
  readonly findings: readonly Finding[];
}

const modeLimits: Readonly<Record<ObservationMode, string>> = {
  synthetic: "Synthetic fixture evidence; it does not establish live coverage.",
  replay: "Replayed evidence; it does not establish live coverage.",
  "vm-live": "VM-live evidence; coverage is limited to the configured lab scope.",
  "physical-live": "Physical-live evidence; coverage is limited to the observed scope.",
};

export function replay(fixtures: readonly unknown[], context: ReplayContext): ReplayResult {
  validateReplayContext(context);
  const observations = [...new Map(fixtures.map((fixture) => {
    const observation = normalizeFixture(fixture, context);
    return [observation.id, observation] as const;
  })).values()].sort((left, right) => left.id.localeCompare(right.id));

  const findings = [
    ...collectorCoverageFindings(observations, context),
    ...observations.flatMap((observation) => evaluateObservation(observation, context.expected_collectors)),
  ].sort((left, right) => left.id.localeCompare(right.id));

  return { observations, findings };
}

function collectorCoverageFindings(observations: readonly Observation[], context: ReplayContext): readonly Finding[] {
  return [...context.expected_collectors]
    .sort((left, right) => `${left.network_scope}:${left.source_id}`.localeCompare(`${right.network_scope}:${right.source_id}`))
    .flatMap((collector) => {
      const status = newestCollectorStatus(observations, collector);
      const mode = status?.mode ?? collector.mode;
      if (status === undefined) {
        return [coverageFinding("collector-missing", "collector-missing", "unknown", collector, mode, "expected collector did not report")];
      }
      if (status.freshness === "stale") {
        return [coverageFinding("collector-stale", "collector-stale", "unknown", collector, mode, "collector status is stale", status)];
      }
      if (status.payload.available === false) {
        return [coverageFinding("collector-unavailable", "collector-unavailable", "unknown", collector, mode, "collector reported unavailable", status)];
      }
      return [];
    });
}

function newestCollectorStatus(observations: readonly Observation[], collector: ExpectedCollector): Observation | undefined {
  return observations
    .filter((observation) => observation.kind === "collector_status" && matchesCollector(observation, collector))
    .reduce<Observation | undefined>((latest, candidate) => {
      if (latest === undefined || candidate.observed_at > latest.observed_at) {
        return candidate;
      }
      if (candidate.observed_at < latest.observed_at) {
        return latest;
      }
      return candidate.payload.available === false && latest.payload.available !== false ? candidate : latest;
    }, undefined);
}

function evaluateObservation(observation: Observation, expectedCollectors: readonly ExpectedCollector[]): readonly Finding[] {
  if (observation.kind === "collector_status" && expectedCollectors.some((collector) => matchesCollector(observation, collector))) {
    return [];
  }
  if (observation.freshness === "stale") {
    return [finding("stale-evidence", "unknown", observation, "observed evidence is older than its configured maximum age")];
  }
  if (observation.kind === "collector_status" && observation.payload.available === false) {
    return [finding("collector-unavailable", "unknown", observation, "collector reported unavailable")];
  }
  if (observation.kind === "dns_query" && normalizeDomain(observation.payload.domain) === "flagged.lab.test") {
    return [finding("flagged-test-domain", "observed", observation, "exact flagged lab domain observed")];
  }
  if (observation.kind === "service_status" && observation.payload.available === false) {
    return [finding("service-unavailable", "observed", observation, "service reported unavailable")];
  }
  return [];
}

function coverageFinding(
  ruleId: string,
  idLabel: string,
  state: FindingState,
  collector: ExpectedCollector,
  mode: ObservationMode,
  reason: string,
  observation?: Observation,
): Finding {
  const coverage: Coverage = { state: "unknown", network_scope: collector.network_scope, source_id: collector.source_id, reason };
  const revision = observation?.evidence_revision ?? digest(`${collector.network_scope}:${collector.source_id}:${reason}`);
  return makeFinding(ruleId, idLabel, state, observation?.id === undefined ? [] : [observation.id], revision, mode, coverage);
}

function finding(ruleId: string, state: FindingState, observation: Observation, reason: string): Finding {
  const coverage: Coverage = { state: state === "unknown" ? "unknown" : "observed", network_scope: observation.network_scope, source_id: observation.source_id, reason };
  return makeFinding(ruleId, ruleId, state, [observation.id], observation.evidence_revision, observation.mode, coverage);
}

function makeFinding(
  ruleId: string,
  idLabel: string,
  state: FindingState,
  evidenceIds: readonly string[],
  revision: string,
  mode: ObservationMode,
  coverage: Coverage,
): Finding {
  return {
    id: `finding:${digest(`${idLabel}:${revision}:${coverage.reason}`)}`,
    rule_id: ruleId,
    state,
    evidence_ids: evidenceIds,
    evidence_revision: revision,
    mode,
    coverage,
    limits: [modeLimits[mode]],
  };
}

function matchesCollector(observation: Observation, collector: ExpectedCollector): boolean {
  return observation.source_id === collector.source_id && observation.network_scope === collector.network_scope;
}

function normalizeDomain(value: unknown): string | undefined {
  if (typeof value !== "string") {
    return undefined;
  }
  return value.toLowerCase().replace(/\.$/, "");
}

function digest(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}
