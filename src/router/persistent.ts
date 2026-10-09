import { createHash, randomBytes } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";

import type { RedactedAuthAttempt } from "./controller.js";
import { classifyDbclient, type Clock, type RouterRunner } from "./runner.js";

const image = "sha256:537d90b97c6f0e99d3ced6af8c0dd1034370ee355ee00332bfa46935b843d767";
const network = "cyber26-router-8j3";
const router = "cyber26-openwrt-lab";

export class PersistentRouterTransport {
  #seed?: string;
  #replacement?: string;
  #createdNetwork = false;
  #createdRouter = false;
  constructor(private readonly runner: RouterRunner, private readonly clock: Clock, private readonly privateDirectory: string) {}

  async prepare(): Promise<void> {
    if ((await this.runner.run({ argv: ["docker", "network", "inspect", network], env: {} })).exit_code === 0 || (await this.runner.run({ argv: ["docker", "inspect", router], env: {} })).exit_code === 0) throw new Error("refusing to adopt a preexisting router lab object");
    mkdirSync(this.privateDirectory, { recursive: true, mode: 0o700 });
    this.#seed = `lab-${randomBytes(3).toString("hex")}`;
    this.#replacement = randomBytes(32).toString("hex");
    writeFileSync(`${this.privateDirectory}/seed`, `${this.#seed}\n`, { mode: 0o600 });
    writeFileSync(`${this.privateDirectory}/recovery`, `${this.#replacement}\n`, { mode: 0o600 });
    const imageId = (await this.checked(["docker", "image", "inspect", image, "--format", "{{.Id}}"])).stdout.trim();
    if (imageId !== image) throw new Error("router image ID does not match the pinned lab image");
    await this.checked(["docker", "network", "create", "--internal", "--label", "cyber26.task=8j3", network]);
    this.#createdNetwork = true;
    await this.checked(["docker", "run", "-d", "--name", router, "--network", network, "--network-alias", "router", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--label", "cyber26.task=8j3", image, "/bin/sh", "-c", "while :; do sleep 3600; done"]);
    this.#createdRouter = true;
    if ((await this.checked(["docker", "network", "inspect", network, "--format", "{{.Internal}}"])).stdout.trim() !== "true") throw new Error("router network is not internal");
    if ((await this.checked(["docker", "inspect", router, "--format", "{{.HostConfig.NetworkMode}} {{.HostConfig.Privileged}} {{if .HostConfig.PortBindings}}bound{{else}}unbound{{end}}"])).stdout.trim() !== `${network} false unbound`) throw new Error("router isolation inspection failed");
    await this.password(this.#seed);
    await this.checked(["docker", "exec", "-d", router, "/usr/sbin/dropbear", "-R", "-E", "-p", "2222"]);
    await Bun.sleep(1000);
    await this.measuredRevision();
  }

  async attack(): Promise<readonly RedactedAuthAttempt[]> {
    if (!this.#seed) throw new Error("router lab is not prepared");
    return [await this.authenticate("unrelated", "invalid-lab-credential"), await this.authenticate("seeded-before", this.#seed)];
  }

  async measuredRevision(): Promise<string> {
    const imageId = (await this.checked(["docker", "image", "inspect", image, "--format", "{{.Id}}"])).stdout.trim();
    if (imageId !== image) throw new Error("router image ID does not match the pinned lab image");
    if ((await this.checked(["docker", "network", "inspect", network, "--format", "{{.Internal}}"])).stdout.trim() !== "true") throw new Error("router network is not internal");
    if ((await this.checked(["docker", "inspect", router, "--format", "{{.HostConfig.NetworkMode}} {{.HostConfig.Privileged}} {{if .HostConfig.PortBindings}}bound{{else}}unbound{{end}}"])).stdout.trim() !== `${network} false unbound`) throw new Error("router isolation inspection failed");
    const containerId = (await this.checked(["docker", "inspect", router, "--format", "{{.Id}}"])).stdout.trim();
    const shadow = (await this.checked(["docker", "exec", router, "/bin/sh", "-c", "sha256sum /etc/shadow | cut -d ' ' -f 1"])).stdout.trim();
    return `sha256:${createHash("sha256").update(JSON.stringify({ containerId, imageId, internal: true, network, shadow })).digest("hex")}`;
  }

  async rotateAndVerify(): Promise<readonly RedactedAuthAttempt[]> {
    if (!this.#seed || !this.#replacement) throw new Error("router lab is not prepared");
    await this.password(this.#replacement);
    await this.checked(["docker", "exec", router, "/bin/sh", "-c", "killall dropbear"]);
    await this.checked(["docker", "exec", "-d", router, "/usr/sbin/dropbear", "-R", "-E", "-p", "2222"]);
    await Bun.sleep(1000);
    return [await this.authenticate("seeded-after", this.#seed), await this.authenticate("replacement", this.#replacement)];
  }

  async cleanup(): Promise<void> { if (this.#createdRouter) await this.runner.run({ argv: ["docker", "rm", "-f", router], env: {} }); if (this.#createdNetwork) await this.runner.run({ argv: ["docker", "network", "rm", network], env: {} }); this.#createdRouter = false; this.#createdNetwork = false; }

  private async password(value: string): Promise<void> { await this.checked(["docker", "exec", "-i", router, "/bin/sh", "-c", "passwd >/dev/null 2>&1"], {}, `${value}\n${value}\n`); }
  private async checked(argv: readonly string[], env: Readonly<Record<string, string | undefined>> = {}, stdin?: string) { const result = await this.runner.run({ argv, env, stdin }); if (result.exit_code !== 0) throw new Error(`router command failed: ${argv.slice(0, 3).join(" ")}`); return result; }
  private async authenticate(role: RedactedAuthAttempt["role"], secret: string): Promise<RedactedAuthAttempt> { const started_at = this.clock.now(); const result = await this.runner.run({ argv: ["docker", "run", "--rm", "--network", network, "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--env", "DROPBEAR_PASSWORD", image, "/usr/bin/dbclient", "-y", "-y", "-T", "-o", "PasswordAuthentication=yes", "-o", "DisableTrivialAuth=yes", "-p", "2222", "root@router", "printf router-authenticated"], env: { DROPBEAR_PASSWORD: secret } }); return { role, started_at, finished_at: this.clock.now(), outcome: result.exit_code === 0 && result.stdout.trim() === "router-authenticated" ? "accepted" : classifyDbclient(result.exit_code === 0 ? 1 : result.exit_code, result.stderr) }; }
}
