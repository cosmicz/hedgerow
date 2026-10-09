// Semgrep rules are only evidence if they can fail: every rule must fire on
// its seeded violation and stay silent on the clean fixtures and on src/.
import { describe, expect, test } from "bun:test";
import { readdirSync } from "node:fs";
import { join, relative } from "node:path";

import { parseSemgrepJson, runSemgrep, scanStatus } from "../../src/adapters/sponsors/semgrep/scan.js";

const live = process.env.RG_SPONSOR_LIVE === "1";
const root = join(import.meta.dir, "../..");
const fixtures = join(import.meta.dir, "fixtures/semgrep");

/** Explicit file targets: Semgrep's default ignore list skips tests/ directories. */
function tsFiles(dir: string): string[] {
  return readdirSync(dir, { recursive: true, encoding: "utf8" })
    .filter((path) => path.endsWith(".ts"))
    .map((path) => relative(root, join(dir, path)))
    .sort();
}

describe("semgrep report parsing", () => {
  test("strips config-path prefixes from rule ids and sorts findings", () => {
    const parsed = parseSemgrepJson(
      JSON.stringify({
        version: "1.180.0",
        results: [
          { check_id: "src.adapters.sponsors.semgrep.rules.rg-no-shell", path: "b.ts", start: { line: 2 } },
          { check_id: "src.adapters.sponsors.semgrep.rules.rg-tls-verification-disabled", path: "a.ts", start: { line: 9 } },
        ],
        errors: [],
        paths: { scanned: ["a.ts", "b.ts"] },
      }),
    );

    expect(parsed.findings).toEqual([
      { rule_id: "rg-tls-verification-disabled", path: "a.ts", line: 9 },
      { rule_id: "rg-no-shell", path: "b.ts", line: 2 },
    ]);
    expect(scanStatus(parsed)).toBe("findings");
  });

  test("errors or an empty scan are never reported as passed", () => {
    expect(scanStatus({ version: "1", findings: [], errors: ["SemgrepError: bad rule"], scanned_files: 3 })).toBe("error");
    expect(scanStatus({ version: "1", findings: [], errors: [], scanned_files: 0 })).toBe("error");
    expect(scanStatus({ version: "1", findings: [], errors: [], scanned_files: 3 })).toBe("passed");
  });

  test("missing tool yields not-run, not passed", async () => {
    const evidence = await runSemgrep({ cwd: root, targets: ["src"], launcher: ["/nonexistent/semgrep"] });

    expect(evidence.status).toBe("not-run");
    expect(evidence.findings).toEqual([]);
  });
});

(live ? describe : describe.skip)("semgrep router-guard rules (live)", () => {
  test("each rule fires on its seeded violation fixture", async () => {
    const evidence = await runSemgrep({ cwd: root, targets: tsFiles(join(fixtures, "violations")) });
    const hits = evidence.findings.map((finding) => `${finding.rule_id} ${finding.path.split("violations/")[1]}:${finding.line}`);

    expect(evidence.status).toBe("findings");
    // Findings are ordered by path, line, rule id.
    expect(hits).toEqual([
      "rg-model-imports-action classifier/judge.ts:2",
      "rg-clickhouse-interpolated-sql clickhouse/query.ts:3",
      "rg-mongo-dynamic-query mongodb/filter.ts:3",
      "rg-mongo-dynamic-query mongodb/filter.ts:3",
      "rg-secret-in-url-or-log secrets.ts:3",
      "rg-secret-in-url-or-log secrets.ts:4",
      "rg-tls-verification-disabled secrets.ts:5",
      "rg-process-spawn-outside-allowlist shell-namespace.ts:2",
      "rg-no-shell shell-namespace.ts:4",
      "rg-process-spawn-outside-allowlist shell.ts:2",
      "rg-no-shell shell.ts:5",
      "rg-no-shell shell.ts:6",
      "rg-no-shell shell.ts:7",
      "rg-process-spawn-outside-allowlist shell.ts:7",
      "rg-process-spawn-outside-allowlist src/actions/service.ts:2",
    ]);
  }, 180_000);

  test("clean fixtures produce no findings", async () => {
    const evidence = await runSemgrep({ cwd: root, targets: tsFiles(join(fixtures, "clean")) });

    expect(evidence.errors).toEqual([]);
    expect(evidence.findings).toEqual([]);
    expect(evidence.status).toBe("passed");
  }, 180_000);

  test("src/ passes the Router Guard rules", async () => {
    const evidence = await runSemgrep({ cwd: root, targets: ["src"] });

    expect(evidence.findings).toEqual([]);
    expect(evidence.status).toBe("passed");
    expect(evidence.version).toBe("1.180.0");
    expect(evidence.revision).toMatch(/^[0-9a-f]{40}$/);
  }, 180_000);
});
