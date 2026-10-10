import { expect, test } from "bun:test";
import traffic from "../../lab/traffic-domains.json";

test("every background domain has a local resolver answer and no external upstream", async () => {
  const compose=await Bun.file(new URL("../../lab/compose.yaml",import.meta.url)).text();
  const hosts=compose.match(/FTLCONF_dns_hosts: "([^"]+)"/)![1]!.split(";");
  expect(hosts).toHaveLength(53);
  for(const domain of traffic.domains)expect(hosts).toContain(`10.77.0.80 ${domain}`);
  expect(compose).toContain('FTLCONF_dns_upstreams: "10.77.0.80#53"');
  expect(compose).toContain("internal: true");
});

test("traffic generator rejects invalid intervals before any DNS lookup", async () => {
  for(const interval of ["0","1","61","nope"]){
    const proc=Bun.spawn(["sh","lab/bin/traffic",interval],{stdout:"pipe",stderr:"pipe"});
    expect(await proc.exited).toBe(2);
    expect(await new Response(proc.stderr).text()).toContain("Interval must be");
  }
});
