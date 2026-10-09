import { describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PersistentRouterTransport } from "../../src/router/persistent";
import { assertAllowedRouterRun, BunRouterRunner, childEnvironment, classifyDbclient, type RouterRun, type RouterRunner } from "../../src/router/runner";

class RecordingRunner implements RouterRunner {
  readonly runs: RouterRun[] = [];
  async run(request: RouterRun) {
    this.runs.push(request);
    const argv=request.argv, command=argv.join(" ");
    if(command==="docker network inspect cyber26-router-8j3" || command==="docker inspect cyber26-openwrt-lab") return {exit_code:1,stdout:"",stderr:"missing"};
    let stdout="";
    if(command.includes("image inspect")) stdout="sha256:537d90b97c6f0e99d3ced6af8c0dd1034370ee355ee00332bfa46935b843d767";
    else if(command.includes("{{.Internal}}")) stdout="true";
    else if(command.includes("HostConfig.NetworkMode")) stdout="cyber26-router-8j3 false unbound";
    else if(command.includes("{{.Id}}")) stdout="container-id";
    else if(command.includes("sha256sum")) stdout="shadow-hash";
    else if(argv.includes("/usr/bin/dbclient")) stdout="router-authenticated";
    return {exit_code:0,stdout,stderr:""};
  }
}
const clock = { now: () => new Date().toISOString() };

describe("router process boundary", () => {
  test("every command the persistent transport issues is on the exact allowlist", async () => {
    const dir = mkdtempSync(join(tmpdir(), "router-runner-"));
    try {
      const runner = new RecordingRunner();
      const transport = new PersistentRouterTransport(runner, clock, join(dir, "private"));
      await transport.prepare(); await transport.attack(); await transport.rotateAndVerify(); await transport.cleanup();
      expect(runner.runs.length).toBeGreaterThan(10);
      for (const run of runner.runs) expect(() => assertAllowedRouterRun(run)).not.toThrow();
      const auth = runner.runs.filter(r => r.argv.includes("/usr/bin/dbclient"));
      expect(auth).toHaveLength(4);
      for (const r of auth) expect(r.argv.some(part => part.includes(r.env.DROPBEAR_PASSWORD!))).toBe(false);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  }, 10_000);

  test("anything else is refused: other binaries, changed or extra arguments, unexpected env or stdin", () => {
    const allowed: RouterRun = { argv: ["docker", "rm", "-f", "cyber26-openwrt-lab"], env: {} };
    expect(() => assertAllowedRouterRun(allowed)).not.toThrow();
    const refused: RouterRun[] = [
      { argv: ["sh", "-c", "docker rm -f cyber26-openwrt-lab"], env: {} },
      { argv: ["docker", "rm", "-f", "some-other-container"], env: {} },
      { argv: ["docker", "rm", "-f", "cyber26-openwrt-lab", "--volumes"], env: {} },
      { argv: ["docker", "network", "create", "--label", "cyber26.task=8j3", "cyber26-router-8j3"], env: {} },
      { argv: ["docker", "run", "-d", "--name", "cyber26-openwrt-lab", "--network", "host", "image"], env: {} },
      { argv: ["docker", "rm", "-f", "cyber26-openwrt-lab"], env: { OPENROUTER_API_KEY: "x" } },
      { argv: ["docker", "rm", "-f", "cyber26-openwrt-lab"], env: { DROPBEAR_PASSWORD: "x" } },
      { argv: ["docker", "rm", "-f", "cyber26-openwrt-lab"], env: {}, stdin: "x\n" },
      { argv: ["docker", "exec", "-i", "cyber26-openwrt-lab", "/bin/sh", "-c", "passwd >/dev/null 2>&1"], env: {} },
    ];
    for (const run of refused) expect(() => assertAllowedRouterRun(run)).toThrow("not on the router allowlist");
  });

  test("the real runner refuses before spawning anything", async () => {
    const marker = join(mkdtempSync(join(tmpdir(), "router-runner-")), "spawned");
    await expect(new BunRouterRunner().run({ argv: ["/bin/sh", "-c", `touch ${marker}`], env: {} })).rejects.toThrow("not on the router allowlist");
    expect(existsSync(marker)).toBe(false);
  });

  test("child processes receive only Docker-relevant parent variables plus the request's secret", () => {
    const env = childEnvironment({ DROPBEAR_PASSWORD: "lab-secret" },
      { PATH: "/usr/bin", HOME: "/Users/lab", DOCKER_CONTEXT: "desktop-linux", OPENROUTER_API_KEY: "sk-or-secret", PIHOLE_API_PASSWORD: "pw" });
    expect(env).toEqual({ PATH: "/usr/bin", HOME: "/Users/lab", DOCKER_CONTEXT: "desktop-linux", DROPBEAR_PASSWORD: "lab-secret" });
  });

  test("Dropbear refusal is rejected; connection failures are errors", () => {
    expect(classifyDbclient(0, "")).toBe("accepted");
    expect(classifyDbclient(1, "dbclient: Connection to root@router:2222 exited: No auth methods could be used.")).toBe("rejected");
    expect(classifyDbclient(1, "Remote closed the connection")).toBe("rejected");
    expect(classifyDbclient(1, "Permission denied")).toBe("rejected");
    expect(classifyDbclient(1, "dbclient: Connection to root@router:2222 exited: Connect failed: Connection refused")).toBe("error");
  });
});
