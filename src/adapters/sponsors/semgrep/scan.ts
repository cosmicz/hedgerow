// Runs Semgrep OSS with the Router Guard rules and turns its JSON into scan
// evidence bound to a git revision. This is the only module outside
// src/executor/ allowed to spawn processes (rg-process-spawn-outside-allowlist):
// argv is fixed, no shell is involved, and no untrusted text reaches it.
// Local rules only; --metrics=off keeps scan data on this machine.
import { fileURLToPath } from "node:url";

export const SEMGREP_VERSION = "1.180.0";
export const RULES_PATH = fileURLToPath(new URL("./rules/router-guard.yml", import.meta.url));

export interface SemgrepFinding {
  readonly rule_id: string;
  readonly path: string;
  readonly line: number;
}

export type ScanStatus = "passed" | "findings" | "error" | "not-run";

export interface SecurityScanEvidence {
  readonly tool: "semgrep";
  readonly status: ScanStatus;
  readonly version: string | null;
  readonly revision: string | null;
  readonly worktree_dirty: boolean | null;
  readonly rules_sha256: string;
  readonly targets: readonly string[];
  readonly scanned_files: number;
  readonly findings: readonly SemgrepFinding[];
  readonly errors: readonly string[];
  readonly duration_ms: number;
  readonly scanned_at: string;
}

export interface ScanOptions {
  readonly cwd: string;
  readonly targets: readonly string[];
  readonly rulesPath?: string;
  readonly timeoutMs?: number;
  /** Replaces the uvx launcher, e.g. to simulate a missing tool. */
  readonly launcher?: readonly string[];
}

interface ParsedScan {
  readonly version: string | null;
  readonly findings: readonly SemgrepFinding[];
  readonly errors: readonly string[];
  readonly scanned_files: number;
}

/** Rule ids from a local config arrive prefixed with the config path; keep the final segment. */
export function parseSemgrepJson(text: string): ParsedScan {
  const report = JSON.parse(text) as {
    version?: string;
    results?: { check_id: string; path: string; start: { line: number } }[];
    errors?: { type?: string; message?: string }[];
    paths?: { scanned?: string[] };
  };
  const findings = (report.results ?? [])
    .map((result) => ({
      rule_id: result.check_id.split(".").at(-1) ?? result.check_id,
      path: result.path,
      line: result.start.line,
    }))
    .sort((a, b) => a.path.localeCompare(b.path) || a.line - b.line || a.rule_id.localeCompare(b.rule_id));
  return {
    version: report.version ?? null,
    findings,
    errors: (report.errors ?? []).map((error) => `${error.type ?? "error"}: ${(error.message ?? "").slice(0, 300)}`),
    scanned_files: report.paths?.scanned?.length ?? 0,
  };
}

export function scanStatus(parsed: ParsedScan): ScanStatus {
  if (parsed.errors.length > 0 || parsed.scanned_files === 0) {
    return "error";
  }
  return parsed.findings.length > 0 ? "findings" : "passed";
}

export async function runSemgrep(options: ScanOptions): Promise<SecurityScanEvidence> {
  const rulesPath = options.rulesPath ?? RULES_PATH;
  const started = performance.now();
  const scanned_at = new Date().toISOString();
  const rules_sha256 = new Bun.CryptoHasher("sha256").update(await Bun.file(rulesPath).arrayBuffer()).digest("hex");
  const { revision, dirty } = await gitRevision(options.cwd);
  const base = { tool: "semgrep" as const, revision, worktree_dirty: dirty, rules_sha256, targets: options.targets, scanned_at };

  const launcher = options.launcher ?? ["uvx", "--from", `semgrep==${SEMGREP_VERSION}`, "semgrep"];
  const argv = [
    ...launcher,
    "scan",
    "--config", rulesPath,
    "--json", "--quiet", "--metrics=off", "--disable-version-check",
    ...options.targets,
  ];
  let output: { stdout: string; exitCode: number };
  try {
    output = await run(argv, options.cwd, options.timeoutMs ?? 120_000);
  } catch (error) {
    return notRun(base, started, `launch failed: ${(error as Error).message}`);
  }
  try {
    const parsed = parseSemgrepJson(output.stdout);
    return { ...base, ...parsed, status: scanStatus(parsed), duration_ms: elapsed(started) };
  } catch {
    return notRun(base, started, `no JSON report (exit ${output.exitCode})`);
  }
}

function notRun(
  base: Omit<SecurityScanEvidence, "status" | "version" | "scanned_files" | "findings" | "errors" | "duration_ms">,
  started: number,
  reason: string,
): SecurityScanEvidence {
  return { ...base, status: "not-run", version: null, scanned_files: 0, findings: [], errors: [reason], duration_ms: elapsed(started) };
}

async function gitRevision(cwd: string): Promise<{ revision: string | null; dirty: boolean | null }> {
  try {
    const head = await run(["git", "rev-parse", "HEAD"], cwd, 10_000);
    const status = await run(["git", "status", "--porcelain"], cwd, 10_000);
    if (head.exitCode !== 0 || status.exitCode !== 0) {
      return { revision: null, dirty: null };
    }
    return { revision: head.stdout.trim(), dirty: status.stdout.trim().length > 0 };
  } catch {
    return { revision: null, dirty: null };
  }
}

async function run(argv: readonly string[], cwd: string, timeoutMs: number): Promise<{ stdout: string; exitCode: number }> {
  const child = Bun.spawn([...argv], { cwd, stdout: "pipe", stderr: "ignore", stdin: "ignore" });
  const timer = setTimeout(() => child.kill(), timeoutMs);
  try {
    const [stdout, exitCode] = await Promise.all([new Response(child.stdout).text(), child.exited]);
    return { stdout, exitCode };
  } finally {
    clearTimeout(timer);
  }
}

function elapsed(started: number): number {
  return Math.round(performance.now() - started);
}
