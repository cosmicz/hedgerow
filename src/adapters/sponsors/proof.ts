// Sponsor proof runner: `bun run sponsors:proof`. Exits non-zero unless every
// check passes.
//
// One flagged-domain scenario, run twice:
//   nominal        — loopback ClickHouse, MongoDB and a fresh Semgrep scan of
//                    the clean HEAD revision; every sponsor must be the backend
//                    that actually served its part.
//   forced-failure — all three sponsors unreachable; the same action lifecycle
//                    must complete on the local fallbacks, visibly degraded,
//                    with evidence identical to the nominal run.
//
// The action lifecycle is the real action core (ActionService + SqliteLedger
// from src/actions) driving SyntheticLab, an in-memory resolver. The sponsor
// stores mirror the ledger's durable event history (JournalMirror), including
// executing and undoing. Mode is SYNTHETIC: no Pi-hole is contacted and no real
// DNS rule changes. Artifacts go to proof/sponsors/ (gitignored until reviewed).
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { SqliteLedger, type ActionEvent } from "../../actions/ledger.js";
import { ActionService } from "../../actions/service.js";
import type { Policy, Proposal } from "../../actions/types.js";
import { JournalMirror, type MirroredEvent } from "./journal-mirror.js";
import { connectClickHouse, connectMongo } from "./proof-connect.js";
import type { SourcedEvidence } from "./resilient.js";
import { BENIGN, FLAGGED } from "./scenario.js";
import { runSemgrep, type SecurityScanEvidence } from "./semgrep/scan.js";
import { SyntheticClock, SyntheticLab } from "./synthetic-lab.js";
import { listenersOn, type PortListeners } from "./tools/listeners.js";
import { PINS, verifyBinaries, type BinaryDigest } from "./tools/pins.js";
import type { ActionRecord, AuditKind, SponsorStatus } from "./types.js";

interface ProofConfig {
  readonly label: "nominal" | "forced-failure";
  readonly clickhouseUrl: string;
  readonly mongoUri: string;
  readonly semgrepLauncher?: readonly string[];
}

interface Check {
  readonly name: string;
  readonly ok: boolean;
  readonly detail: string;
}

interface ScenarioReport {
  readonly label: ProofConfig["label"];
  readonly mode: "synthetic";
  readonly network_scope: string;
  readonly statuses: readonly SponsorStatus[];
  readonly finding_evidence: SourcedEvidence;
  readonly rule_window_evidence: { readonly flagged: SourcedEvidence; readonly benign: SourcedEvidence } | null;
  readonly journal: readonly ActionEvent[];
  readonly mirrored: readonly MirroredEvent[];
  readonly executed: ActionRecord;
  readonly duplicate_execute: ActionRecord;
  readonly undone: ActionRecord;
  readonly rule_creates: number;
  readonly rule_present_after_undo: boolean;
  readonly projection_history: readonly string[];
  readonly journal_audit: readonly AuditKind[];
  readonly projection_durable: boolean;
  readonly stale_publish_rejected: boolean;
  readonly audit_trail: readonly AuditKind[];
  readonly security_scan: SecurityScanEvidence;
  readonly listeners: readonly PortListeners[];
  readonly binaries: readonly BinaryDigest[];
}

const START = Date.parse("2026-10-09T20:00:00.000Z");
const PROBE_CLIENT = "192.0.2.53";
const PROOF_AUDIT: readonly AuditKind[] = ["finding_evidence", "security_scan"];
const repoRoot = join(import.meta.dir, "../../..");

const iso = (ms: number) => new Date(ms).toISOString();

async function runScenario(config: ProofConfig, runId: string): Promise<ScenarioReport> {
  const scope = `lab-proof-${config.label}-${runId}`;
  const clock = new SyntheticClock(START);
  const lab = new SyntheticLab({ network_scope: scope, clock, probe_client: PROBE_CLIENT, benign_domain: BENIGN });
  const store = await connectClickHouse(config.clickhouseUrl);
  const { projection, client } = await connectMongo(config.mongoUri, `action_revisions_${runId}`);
  let ledger: SqliteLedger | null = null;
  // Everything after the Mongo client exists runs inside try, so finally always closes it.
  try {
    const ledgerDir = join(repoRoot, "private/proof-ledgers");
    mkdirSync(ledgerDir, { recursive: true });
    ledger = new SqliteLedger(join(ledgerDir, `${runId}-${config.label}.sqlite`), () => clock.now());
    const mirror = new JournalMirror(ledger, projection, store);
    const subject = `proof:${config.label}:${runId}`;
    let auditSeq = 0;
    const audit = (kind: AuditKind, detail: unknown) =>
      store.appendAudit({ id: `${subject}:${++auditSeq}`, at: iso(clock.now()), subject_id: subject, kind, detail: JSON.stringify(detail) });

    // 1. Lab clients resolve the flagged name; the resolver's own lookups become observations.
    lab.lookup(FLAGGED, "192.0.2.10");
    lab.lookup(FLAGGED, "192.0.2.11");
    lab.lookup(BENIGN, "192.0.2.10");
    lab.lookup(FLAGGED, "192.0.2.10");
    await store.record(lab.drain());
    const finding_evidence = await store.sourcedEvidence({ domain: FLAGGED, network_scope: scope, from: iso(START), to: iso(clock.now()) });
    await audit("finding_evidence", { backend: finding_evidence.backend, observation_ids: finding_evidence.evidence.observation_ids });

    // 2. The action core owns proposal, approval, execution and undo.
    const evidenceRevision = `evidence:${new Bun.CryptoHasher("sha256").update(JSON.stringify(finding_evidence.evidence.observation_ids)).digest("hex").slice(0, 16)}`;
    const policy: Policy = { network_scope: scope, resolver_id: "synthetic-resolver", group_id: 2, allowed_domains: [FLAGGED], max_duration_ms: 3_600_000 };
    const service = new ActionService({
      ledger,
      adapter: lab.adapter,
      policy,
      verify: lab.verify,
      now: () => clock.now(),
      evidence_revision: () => evidenceRevision,
    });
    const created_at = clock.now();
    const proposal: Proposal = {
      action: "dns-deny",
      network_scope: scope,
      resolver_id: "synthetic-resolver",
      domain: FLAGGED,
      group_id: 2,
      evidence_revision: evidenceRevision,
      created_at,
      expires_at: created_at + 600_000,
    };

    // 3. After each operation, mirror the ledger's durable history: MongoDB projection + ClickHouse audit.
    const proposed = service.propose(proposal);
    await mirror.sync(proposed.digest);
    service.approve(proposed.digest, "operator:proof");
    await mirror.sync(proposed.digest);
    const executed = await service.execute(proposed.digest);
    await store.record(lab.drain());
    await mirror.sync(proposed.digest);
    const duplicate_execute = await service.execute(proposed.digest);
    const undone = await service.undo(proposed.digest);
    await store.record(lab.drain());
    const mirrored = await mirror.sync(proposed.digest);
    const stale = await projection.publish({ ...proposed, detail: "stale publisher" }, 1);

    // 4. Independent ClickHouse view of the rule's lifetime: flagged blocked, benign still answered.
    const window = lab.ruleWindows[0];
    const rule_window_evidence = window
      ? {
          flagged: await store.sourcedEvidence({ domain: FLAGGED, network_scope: scope, from: iso(window.created_at), to: iso(window.removed_at ?? clock.now()) }),
          benign: await store.sourcedEvidence({ domain: BENIGN, network_scope: scope, from: iso(window.created_at), to: iso(window.removed_at ?? clock.now()) }),
        }
      : null;

    // 5. Fresh Semgrep scan of this revision, recorded in the same audit trail.
    const security_scan = await runSemgrep({ cwd: repoRoot, targets: ["src"], launcher: config.semgrepLauncher });
    await audit("security_scan", { status: security_scan.status, revision: security_scan.revision, findings: security_scan.findings.length });

    const scanStatus: SponsorStatus = {
      sponsor: "semgrep",
      health: security_scan.status === "passed" || security_scan.status === "findings" ? "ok" : "unavailable",
      serving_backend: security_scan.status === "not-run" ? "none" : "semgrep-oss",
      version: security_scan.version,
      detail: `scan ${security_scan.status}: ${security_scan.findings.length} findings in ${security_scan.scanned_files} files`,
      latency_ms: security_scan.duration_ms,
    };

    const ports = [new URL(config.clickhouseUrl).port, new URL(config.mongoUri.replace(/^mongodb:/, "http:")).port].map(Number);
    return {
      label: config.label,
      mode: "synthetic",
      network_scope: scope,
      statuses: [store.status(), projection.status(), scanStatus],
      finding_evidence,
      rule_window_evidence,
      journal: ledger.history(proposed.digest),
      mirrored,
      executed,
      duplicate_execute,
      undone,
      rule_creates: lab.creates,
      rule_present_after_undo: lab.hasRule(FLAGGED),
      projection_history: (await projection.history(proposed.digest)).map((entry) => `${entry.revision}:${entry.status}`),
      projection_durable: projection.durable,
      journal_audit: (await store.auditTrail(`journal:${proposed.digest}`)).map((event) => event.kind),
      stale_publish_rejected: !stale.ok,
      audit_trail: (await store.auditTrail(subject)).map((event) => event.kind),
      security_scan,
      listeners: config.label === "nominal" ? await Promise.all(ports.map(listenersOn)) : [],
      binaries: config.label === "nominal" ? await verifyBinaries(process.env.RG_SPONSOR_TOOLS) : [],
    };
  } finally {
    ledger?.close();
    await client?.close();
  }
}

function lifecycleChecks(report: ScenarioReport): Check[] {
  const window = report.rule_window_evidence;
  const journalStatuses = report.journal.map((event) => event.status);
  const times = report.journal.map((event) => event.at);
  const event = (status: string) => report.journal.find((entry) => entry.status === status);
  return [
    check("action executed and verified by the action core", report.executed.status === "active" &&
      report.executed.verification?.target === "blocked" && report.executed.verification.benign === "resolved" &&
      report.executed.verification.mode === "synthetic", `${report.executed.status} ${JSON.stringify(report.executed.verification)}`),
    check("duplicate execute changes nothing", report.duplicate_execute.status === "active" && report.rule_creates === 1, `creates=${report.rule_creates}`),
    check("undo reverted and rule absent", report.undone.status === "reverted" && !report.rule_present_after_undo, report.undone.status),
    check("journal records executing and undoing with timestamps", ["executing", "undoing"].every((status) => event(status)) &&
      times.every((at, index) => at !== null && (index === 0 || at > times[index - 1]!)) &&
      event("active")?.verification?.target === "blocked" && event("reverted")?.verification?.target === "resolved",
      report.journal.map((entry) => `${entry.seq}:${entry.status}@${entry.at}`).join(">")),
    check("projection mirrors the journal", same(report.projection_history, ["proposed", ...journalStatuses].map((status, index) => `${index + 1}:${status}`)),
      report.projection_history.join(">")),
    check("journal audit in store mirrors the journal", same(report.journal_audit, ["proposed", ...journalStatuses]), report.journal_audit.join(">")),
    check("stale projection publish rejected", report.stale_publish_rejected, ""),
    check("finding evidence: 3 flagged lookups from 2 clients", report.finding_evidence.evidence.lookups === 3 &&
      same(report.finding_evidence.evidence.clients, ["192.0.2.10", "192.0.2.11"]), JSON.stringify(report.finding_evidence.evidence.clients)),
    check("rule window: flagged only blocked, benign answered", window !== null && window.flagged.evidence.outcomes.blocked > 0 &&
      window.flagged.evidence.outcomes.answered === 0 && window.benign.evidence.outcomes.answered > 0,
      JSON.stringify(window && { flagged: window.flagged.evidence.outcomes, benign: window.benign.evidence.outcomes })),
    check("proof audit trail", same(report.audit_trail, PROOF_AUDIT), report.audit_trail.join(">")),
  ];
}

function nominalChecks(report: ScenarioReport): Check[] {
  const [clickhouse, mongodb, semgrep] = report.statuses as [SponsorStatus, SponsorStatus, SponsorStatus];
  const scan = report.security_scan;
  const window = report.rule_window_evidence;
  const evidenceBackends = [report.finding_evidence, window?.flagged, window?.benign].map((entry) => entry?.backend);
  return [
    check("clickhouse served evidence and audit at the pinned version", clickhouse.health === "ok" && clickhouse.version === PINS.clickhouse.version &&
      evidenceBackends.every((backend) => backend === "clickhouse"), `${clickhouse.health} ${clickhouse.version} ${evidenceBackends.join(",")}`),
    check("mongodb durable projection at the pinned version", mongodb.health === "ok" && mongodb.version === PINS.mongodb.version &&
      report.projection_durable, `${mongodb.health} ${mongodb.version}`),
    check("semgrep passed on clean exact revision", semgrep.health === "ok" && scan.status === "passed" && scan.findings.length === 0 &&
      scan.version === PINS.semgrep.version && scan.revision !== null && scan.worktree_dirty === false,
      `${scan.status} ${scan.version} ${scan.revision} dirty=${scan.worktree_dirty}`),
    check("sponsor services listen on loopback only", report.listeners.length === 2 && report.listeners.every((entry) => entry.loopback_only),
      report.listeners.map((entry) => entry.addresses.join("|")).join(" ")),
    check("pinned binaries verified in RG_SPONSOR_TOOLS", report.binaries.length === 2 && report.binaries.every((entry) => entry.matches),
      report.binaries.map((entry) => `${entry.binary}=${entry.actual_sha256?.slice(0, 12) ?? "missing"}`).join(" ")),
    ...lifecycleChecks(report),
  ];
}

function failureChecks(report: ScenarioReport, nominal: ScenarioReport): Check[] {
  const strip = (entry: SourcedEvidence) => JSON.stringify({ ...entry.evidence, network_scope: null });
  return [
    check("all sponsors visibly not ok", report.statuses.every((status) => status.health !== "ok"), report.statuses.map((status) => status.health).join(",")),
    check("fallbacks serve locally", report.finding_evidence.backend === "local" && !report.projection_durable && report.security_scan.status === "not-run", ""),
    check("fallback evidence equals nominal evidence", strip(report.finding_evidence) === strip(nominal.finding_evidence), ""),
    ...lifecycleChecks(report),
  ];
}

function check(name: string, ok: boolean, detail: string): Check {
  return { name, ok, detail };
}

function same(a: readonly string[], b: readonly string[]): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

function markdown(runId: string, reports: readonly ScenarioReport[], checks: Readonly<Record<string, readonly Check[]>>): string {
  const lines = [
    `# Router Guard sponsor proof ${runId}`,
    "",
    "Mode: SYNTHETIC. The real action core (ActionService + SqliteLedger) drives an in-memory",
    "resolver; sponsor stores mirror its durable journal history. No Pi-hole is contacted and no",
    "real DNS rule changes. Reserved .test names and",
    "RFC 5737 addresses only. MongoDB sponsor eligibility is unconfirmed.",
    "",
  ];
  for (const report of reports) {
    lines.push(`## ${report.label}`, "", "| Sponsor | Health | Serving | Version | Latency ms | Detail |", "|---|---|---|---|---|---|");
    for (const status of report.statuses) {
      lines.push(`| ${status.sponsor} | ${status.health} | ${status.serving_backend} | ${status.version ?? "-"} | ${status.latency_ms ?? "-"} | ${status.detail} |`);
    }
    const evidence = report.finding_evidence.evidence;
    lines.push(
      "",
      `- Finding evidence (${report.finding_evidence.backend}, ${report.finding_evidence.latency_ms} ms): ${evidence.lookups} lookups of ${evidence.domain} by ${evidence.clients.join(", ")}`,
      `- Journal (SqliteLedger history): ${report.journal.map((entry) => `${entry.seq}:${entry.status}@${entry.at === null ? "unknown" : new Date(entry.at).toISOString()}`).join(" -> ")}`,
      `- Journal audit (store): ${report.journal_audit.join(" -> ")}`,
      `- Projection: ${report.projection_history.join(" -> ")} (durable: ${report.projection_durable})`,
      `- Audit trail: ${report.audit_trail.join(" -> ")}`,
      `- Semgrep: ${report.security_scan.status} at ${report.security_scan.revision ?? "unknown"} (dirty: ${report.security_scan.worktree_dirty})`,
      ...report.listeners.map((entry) => `- Port ${entry.port} listeners: ${entry.addresses.join(", ") || "none"}`),
      ...report.binaries.map((entry) => `- ${entry.binary} sha256 ${entry.actual_sha256 ?? "missing"} (pinned match: ${entry.matches})`),
      "",
      "| Check | Result | Detail |",
      "|---|---|---|",
      ...(checks[report.label] ?? []).map((entry) => `| ${entry.name} | ${entry.ok ? "PASS" : "FAIL"} | ${entry.detail.replaceAll("|", "/")} |`),
      "",
    );
  }
  return lines.join("\n");
}

async function main(): Promise<void> {
  const runId = new Date().toISOString().replace(/[:.]/g, "-");
  const nominalConfig: ProofConfig = {
    label: "nominal",
    clickhouseUrl: process.env.RG_CLICKHOUSE_URL ?? "http://127.0.0.1:18123",
    mongoUri: process.env.RG_MONGO_URI ?? "mongodb://127.0.0.1:27717",
  };
  // Port 9 (discard) on loopback is expected closed; failureChecks verify every sponsor was unreachable.
  const failureConfig: ProofConfig = {
    label: "forced-failure",
    clickhouseUrl: "http://127.0.0.1:9",
    mongoUri: "mongodb://127.0.0.1:9",
    semgrepLauncher: ["/nonexistent/semgrep"],
  };

  const nominal = await runScenario(nominalConfig, runId);
  const failed = await runScenario(failureConfig, runId);
  const checks = { nominal: nominalChecks(nominal), "forced-failure": failureChecks(failed, nominal) };
  const passed = Object.values(checks).flat().every((entry) => entry.ok);

  const outDir = join(repoRoot, "proof/sponsors");
  mkdirSync(outDir, { recursive: true });
  const base = join(outDir, runId);
  const report = markdown(runId, [nominal, failed], checks);
  writeFileSync(`${base}.json`, `${JSON.stringify({ run_id: runId, mode: "synthetic", passed, checks, reports: [nominal, failed] }, null, 2)}\n`);
  writeFileSync(`${base}.md`, `${report}\nOverall: ${passed ? "PASS" : "FAIL"}\n`);
  console.log(report);
  console.log(`Overall: ${passed ? "PASS" : "FAIL"}`);
  console.log(`wrote proof/sponsors/${runId}.{json,md}`);
  process.exitCode = passed ? 0 : 1;
}

await main();
