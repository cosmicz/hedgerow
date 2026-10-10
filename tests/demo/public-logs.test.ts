import { expect, test } from "bun:test";
import { runInNewContext } from "node:vm";

test("live table renders readable records without the removed diagnostic section", async () => {
  const html=await Bun.file(new URL("../../src/demo/public/index.html",import.meta.url)).text();
  class Element {
    children: Element[]=[]; textContent=""; dataset:Record<string,string>={};
    append(...children:Element[]){this.children.push(...children);}
    replaceChildren(){this.children=[];}
    querySelectorAll(){return [];}
    addEventListener(){}
  }
  const elements=new Map([...html.matchAll(/id="([^"]+)"/g)].map(m=>[m[1]!,new Element()]));
  let selection="";
  const context={getSelection:()=>({toString:()=>selection}),document:{getElementById:(id:string)=>elements.get(id)??null,createElement:()=>new Element(),querySelectorAll:()=>[]},fetch:()=>new Promise(()=>{}),setInterval:()=>0};
  const source=await Bun.file(new URL("../../src/demo/public/app.js",import.meta.url)).text();
  const row={id:"pihole:query:253",observed_at:1000,captured_at:2000,domain:"google.com",client:"10.77.0.100",type:"A",status:"CACHE",reply:"IP"};
  runInNewContext(source+"\nrender("+JSON.stringify({logs:{status:"live",rows:[row],events:[]},actions:[],judgments:[],traces:[]})+");",context);
  const cells=elements.get("captured-rows")!.children[0]!.children;
  expect(cells.map(c=>c.textContent).slice(1)).toEqual(["10.77.0.100","google.com","Resolved (cached)"]);
  expect(cells.every(c=>c.children.length===0)).toBe(true);
  expect(elements.get("log-status")!.textContent).toBe("Live");
  expect(html).not.toContain("Log details");
  expect(html).not.toContain("Probe evidence remains");
  expect(html).toContain("Technical details");
  selection="google.com";
  runInNewContext("render({logs:{status:'live',rows:[],events:[]},actions:[],judgments:[],traces:[]})",context);
  expect(elements.get("captured-rows")!.children).toHaveLength(1);
  selection="";
  runInNewContext("render({logs:{status:'live',rows:[],events:[]},actions:[],judgments:[],traces:[]})",context);
  expect(elements.get("captured-rows")!.children[0]!.children[0]!.textContent).toBe("Waiting for device logs…");
});
