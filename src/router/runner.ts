export interface RouterRun { readonly argv: readonly string[]; readonly env: Readonly<Record<string, string | undefined>>; readonly stdin?: string; }
export interface RouterRunResult { readonly exit_code: number; readonly stdout: string; readonly stderr: string; }
export interface RouterRunner { run(request: RouterRun): Promise<RouterRunResult>; }

// Fixed lab identity. These must match src/router/persistent.ts; the runner test drives the real
// transport through a recording runner, so any drift in an issued command fails that test.
const image = "sha256:537d90b97c6f0e99d3ced6af8c0dd1034370ee355ee00332bfa46935b843d767";
const network = "cyber26-router-8j3";
const router = "cyber26-openwrt-lab";
const label = "cyber26.task=8j3";

interface AllowedCommand { readonly argv: readonly string[]; readonly env?: readonly string[]; readonly stdin?: true; }
/**
 * Every process the router transport may start, as exact argv. No shell, no caller-supplied
 * arguments: secrets travel only in the named env variable or on stdin, never in argv.
 */
export const ROUTER_COMMANDS: readonly AllowedCommand[] = [
  { argv: ["docker", "network", "inspect", network] },
  { argv: ["docker", "inspect", router] },
  { argv: ["docker", "inspect", router, "--format", "{{.Id}}"] },
  { argv: ["docker", "exec", router, "/bin/sh", "-c", "sha256sum /etc/shadow | cut -d ' ' -f 1"] },
  { argv: ["docker", "image", "inspect", image, "--format", "{{.Id}}"] },
  { argv: ["docker", "network", "create", "--internal", "--label", label, network] },
  { argv: ["docker", "run", "-d", "--name", router, "--network", network, "--network-alias", "router", "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges", "--label", label, image, "/bin/sh", "-c", "while :; do sleep 3600; done"] },
  { argv: ["docker", "network", "inspect", network, "--format", "{{.Internal}}"] },
  { argv: ["docker", "inspect", router, "--format", "{{.HostConfig.NetworkMode}} {{.HostConfig.Privileged}} {{if .HostConfig.PortBindings}}bound{{else}}unbound{{end}}"] },
  { argv: ["docker", "exec", "-i", router, "/bin/sh", "-c", "passwd >/dev/null 2>&1"], stdin: true },
  { argv: ["docker", "exec", "-d", router, "/usr/sbin/dropbear", "-R", "-E", "-p", "2222"] },
  { argv: ["docker", "exec", router, "/bin/sh", "-c", "killall dropbear"] },
  { argv: ["docker", "run", "--rm", "--network", network, "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
    "--env", "DROPBEAR_PASSWORD", image, "/usr/bin/dbclient", "-y", "-y", "-T", "-o", "PasswordAuthentication=yes",
    "-o", "DisableTrivialAuth=yes", "-p", "2222", "root@router", "printf router-authenticated"], env: ["DROPBEAR_PASSWORD"] },
  { argv: ["docker", "rm", "-f", router] },
  { argv: ["docker", "network", "rm", network] },
];

export function assertAllowedRouterRun(request: RouterRun): void {
  const envKeys = Object.keys(request.env ?? {}).filter(key => request.env[key] !== undefined);
  const allowed = ROUTER_COMMANDS.some(command =>
    command.argv.length === request.argv.length && command.argv.every((part, i) => part === request.argv[i]) &&
    envKeys.every(key => command.env?.includes(key) && typeof request.env[key] === "string" && request.env[key] !== "") &&
    (command.env ?? []).every(key => envKeys.includes(key)) &&
    (command.stdin === true) === (typeof request.stdin === "string"));
  // Never echo argv or env: they may sit next to lab credentials.
  if (!allowed) throw new Error("Command is not on the router allowlist");
}

/** Parent variables Docker's CLI needs to reach its daemon/context. API keys and lab passwords are not inherited. */
const inheritedEnv = ["PATH", "HOME", "USER", "TMPDIR", "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "DOCKER_CERT_PATH", "DOCKER_TLS_VERIFY"];
export function childEnvironment(requestEnv: Readonly<Record<string, string | undefined>>,
  parentEnv: Readonly<Record<string, string | undefined>> = process.env): Record<string, string> {
  const env: Record<string, string> = {};
  for (const key of inheritedEnv) { const value = parentEnv[key]; if (value !== undefined) env[key] = value; }
  for (const [key, value] of Object.entries(requestEnv)) if (value !== undefined) env[key] = value;
  return env;
}

export class BunRouterRunner implements RouterRunner {
  async run(request: RouterRun): Promise<RouterRunResult> {
    assertAllowedRouterRun(request);
    const options = { env: childEnvironment(request.env), stdout: "pipe" as const, stderr: "pipe" as const,
      ...(request.stdin === undefined ? {} : { stdin: new TextEncoder().encode(request.stdin) }) };
    // Reviewed exception to rg-process-spawn-outside-allowlist: argv is checked against ROUTER_COMMANDS above.
    const child = Bun.spawn([...request.argv], options); // nosemgrep: src.adapters.sponsors.semgrep.rules.rg-process-spawn-outside-allowlist
    const stdout = new Response(child.stdout).text(); const stderr = new Response(child.stderr).text();
    const timer = setTimeout(() => child.kill(), 20000);
    try {
      const [exit_code, output, errors] = await Promise.all([child.exited, stdout, stderr]);
      return { exit_code, stdout: output, stderr: errors };
    } finally { clearTimeout(timer); }
  }
}
// "Remote closed the connection" is the measured wrong-password result in this lab, but alone it is
// ambiguous (a dying server closes too). Callers must pair it with a known-accepted attempt.
export function classifyDbclient(exitCode: number, stderr: string): "accepted" | "rejected" | "error" { if (exitCode === 0) return "accepted"; return /permission denied|authentication failed|access denied|no auth methods could be used|no authentication methods available|remote closed the connection/i.test(stderr) ? "rejected" : "error"; }
export interface Clock { now(): string; }
export const systemClock: Clock = { now: () => new Date().toISOString() };
