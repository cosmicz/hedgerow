import { expect, test } from "bun:test";
import { SqliteLedger, type Rule } from "../../src/actions";
import { DemoController } from "../../src/demo/controller";
import { collectQueryEvidence } from "../../src/demo/evidence";
import { SponsorBridge } from "../../src/adapters/sponsors";
import { DemoSponsors } from "../../src/demo/sponsors";
import { CapturedLogs } from "../../src/demo/logs";
import { DemoChat } from "../../src/demo/chat";

test("a pending read-only chat does not hold the action lock", async () => {
  let release!: (response: Response) => void;
  const chat = new DemoChat({ apiKey: "test-key", fetch: async () => new Promise<Response>(resolve => { release = resolve; }) });
  const ledger = new SqliteLedger(":memory:");
  const controller = new DemoController({ ledger, group: 1, now: Date.now, chat,
    adapter: { read: async () => null, create: async () => {}, remove: async () => {} },
    verify: async () => { throw Error("unused"); }, collect: async () => { throw Error("unused"); }, classifiers: [],
    agent: { model: "fixture", provenance: "fake", respond: async () => ({}) } });
  try {
    const pending = controller.command("chat", { message: "What changed?" });
    while (!release) await Bun.sleep(1);
    await expect(controller.command("reset", {})).resolves.toMatchObject({ finding: null });
    await expect(controller.command("chat", { message: "Still there?" })).rejects.toThrow("Operation in progress");
    release(new Response(JSON.stringify({ choices: [{ message: { content: "No action has been taken." } }] }), { headers: { "content-type": "application/json" } }));
    await expect(pending).resolves.toMatchObject({ chat: { messages: [{ role: "user" }, { role: "assistant" }] } });
  } finally { ledger.close(); }
});

test("hybrid deployment label does not relabel VM probe evidence as physical", () => {
  const ledger=new SqliteLedger(":memory:");
  const controller=new DemoController({ledger,group:1,now:Date.now,deployment:"pi-hybrid",
    adapter:{read:async()=>null,create:async()=>{},remove:async()=>{}},
    verify:async()=>{throw Error("unused");},collect:async()=>{throw Error("unused");},classifiers:[],
    agent:{model:"fixture",provenance:"fake",respond:async()=>({})}});
  expect(controller.state().topology).toContain("Pi-hosted controller");
  expect(controller.state().mode).toBe("vm-live");
  ledger.close();
});

test.each(["none", "unavailable", "failed", "hung"] as const)("controller keeps approval authority with sponsor mode %s", async mode => {
  let now = 1_800_000_000_000;
  let rule: Rule | null = null;
  let round = 0;
  const ledger = new SqliteLedger(":memory:", () => now);
  const logs = new CapturedLogs(":memory:", async()=>({queries:[]}),()=>now);
  const bridge = await SponsorBridge.open({});
  if (mode === "failed") bridge.recordObservations = async () => { throw new Error("private backend failure"); };
  const sponsors = mode === "none" ? undefined : new DemoSponsors(bridge, mode === "hung" ? 100 : 2000);
  const controller = new DemoController({ ledger, now: () => now, group: 1,
    sponsors, logs,
    adapter: { read: async () => rule, create: async r => { rule = r; }, remove: async () => { rule = null; } },
    verify: async () => ({ target: rule ? "blocked" : "resolved", benign: "resolved", checked_at: now, mode: "synthetic" }),
    collect: async from => {
      expect(from).toBe(now);
      return collectQueryEvidence({ queries: [{ id: 1, time: now / 1000, domain: "flagged.lab.test", type: "A", client: { ip: "10.77.0.100" } }] }, from, now);
    },
    classifiers: [],
    agent: { model: "test", provenance: "fake", respond: async input => {
      const initial = JSON.parse((input[0] as any).content);
      if (++round === 1) return { output: [{ type: "function_call", name: "propose_dns_deny", call_id: "propose1", arguments: JSON.stringify({ evidence_revision: initial.evidence_revision }) }] };
      if (round === 2) {
        const proposed = JSON.parse((input.filter((x: any) => x.type === "function_call_output").at(-1) as any).output);
        return { output: [{ type: "function_call", name: "execute_approved", call_id: "execute1", arguments: JSON.stringify({ digest: proposed.digest }) }] };
      }
      const last = JSON.parse((input.at(-1) as any).content);
      return { output: [{ type: "message", content: [{ type: "output_text", text: JSON.stringify({ text: "Test interpretation", citations: [last.authoritative_traces.at(-1).id] }) }] }] };
    } },
  });
  try {
    await expect(controller.command("propose", {})).rejects.toThrow();
    await controller.command("observe", {});
    await controller.command("classify", {});
    expect(controller.state().logs?.events.some(e=>e.kind==="model-result"&&e.evidence_refs.includes("pihole:query:1"))).toBe(true);
    await controller.command("propose", {});
    const digest = controller.state().actions[0]!.digest;
    expect(rule).toBeNull();
    await expect(controller.command("execute", { digest })).rejects.toThrow();
    await controller.command("approve", { digest });
    await sponsors?.settled();
    if (mode === "hung") bridge.mirrorJournal = () => new Promise(() => {});
    now += 1; // A later proposal must have a different digest; a frozen clock hides this defect.
    expect(await Promise.race([controller.command("execute", { digest }).then(() => "returned"), Bun.sleep(50).then(() => "blocked")])).toBe("returned");
    expect(rule).not.toBeNull();
    await expect(controller.command("reset", {})).rejects.toThrow();
    expect(rule).not.toBeNull();
    expect(controller.state().actions[0]!.status).toBe("active");
    expect(controller.state().actions).toHaveLength(1);
    expect(controller.state().agent?.calls.some(c => c.name === "execute_approved" && c.ok)).toBe(true);
    expect(controller.state().logs?.events.some(e=>e.kind==="agent-tool"&&e.summary.includes("execute_approved"))).toBe(true);
    expect(await Promise.race([controller.command("undo", { digest }).then(() => "returned"), Bun.sleep(50).then(() => "blocked")])).toBe("returned");
    await sponsors?.settled();
    expect(rule).toBeNull();
    expect(controller.state().actions[0]!.status).toBe("reverted");
    expect(controller.state().agent_at).toBe(now);
    if (mode === "unavailable") {
      const audit = controller.state().sponsors!;
      expect(audit.evidence?.backend).toBe("local");
      expect(audit.evidence?.evidence.lookups).toBe(1);
      expect(audit.actions?.value.find(a => a.digest === digest)?.status).toBe("reverted");
      expect(audit.report.sponsors.every(s => s.health === "unavailable")).toBe(true);
      expect((await bridge.actionHistory(digest)).value.map(a => a.status)).toEqual(["proposed", ...ledger.history(digest).map(e => e.status)]);
    } else if (mode === "failed") {
      expect(controller.state().sponsors?.error).toBe("Sponsor evidence is unavailable; the local action journal remains authoritative.");
      expect(JSON.stringify(controller.state().sponsors)).not.toContain("private backend failure");
    } else if (mode === "hung") {
      expect(controller.state().sponsors?.error).toContain("timed out");
    }
    now += 61_000;
    await expect(controller.command("propose", {})).rejects.toThrow();
    await controller.command("reset", {});
    expect(controller.state().finding).toBeNull();
    expect(controller.state().agent).toBeNull();
    expect(controller.state().logs?.events.length).toBeGreaterThan(0);
    expect(controller.state().traces).toHaveLength(0);
    expect(ledger.get(digest).status).toBe("reverted");
    await controller.command("observe", {});
    await controller.command("propose", {});
    const unused = controller.state().actions.at(-1)!.digest;
    await controller.command("approve", { digest: unused });
    await controller.command("reset", {});
    expect(ledger.get(unused).status).toBe("revoked");
    expect(ledger.history(unused).at(-1)?.status).toBe("revoked");
    await expect(controller.command("execute", { digest: unused })).rejects.toThrow();
  } finally { ledger.close(); logs.close(); await bridge.close(); }
});
