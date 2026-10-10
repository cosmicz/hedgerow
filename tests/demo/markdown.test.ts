import { expect, test } from "bun:test";
import { runInNewContext } from "node:vm";

class Element {
  children:Element[]=[]; textContent=""; dataset={}; href=""; rel="";
  constructor(readonly tag:string){}
  append(...children:Element[]){this.children.push(...children);}
  addEventListener(){}
}
async function renderMarkdown(text:string){
  const document={getElementById:()=>new Element("div"),createElement:(tag:string)=>new Element(tag),querySelectorAll:()=>[]};
  const source=await Bun.file(new URL("../../src/demo/public/app.js",import.meta.url)).text();
  return runInNewContext(source+"\nmarkdown("+JSON.stringify(text)+")",{document,fetch:()=>new Promise(()=>{}),setInterval:()=>0,URL}) as Element;
}
const all=(e:Element):Element[]=>[e,...e.children.flatMap(all)];
test("agent Markdown renders headings, lists, emphasis, links and code as elements",async()=>{
  const root=await renderMarkdown("### Confidence / classification\n- **Category:** suspicious\n- *Confidence:* moderate\n\n### Relevant controls\n1. **Short incident summary**\n2. `next step`\n\n[Reference](https://example.com)\n\n```sh\necho hello\n```");
  const nodes=all(root);
  expect(nodes.filter(n=>n.tag==="h3").map(n=>all(n).map(x=>x.textContent).join(""))).toEqual(["Confidence / classification","Relevant controls"]);
  expect(nodes.filter(n=>n.tag==="ul")).toHaveLength(1);
  expect(nodes.filter(n=>n.tag==="ol")).toHaveLength(1);
  expect(nodes.filter(n=>n.tag==="li")).toHaveLength(4);
  expect(nodes.some(n=>n.tag==="strong"&&all(n).some(x=>x.textContent==="Category:"))).toBe(true);
  expect(nodes.some(n=>n.tag==="em")).toBe(true);
  expect(nodes.find(n=>n.tag==="a")?.href).toBe("https://example.com/");
  expect(nodes.some(n=>n.tag==="pre")).toBe(true);
});
test("remote HTML and script links remain inert text",async()=>{
  const nodes=all(await renderMarkdown('<img src=x onerror=alert(1)>\n\n[click](javascript:alert)\n\n**<script>bad</script>**'));
  expect(nodes.some(n=>["img","script","a"].includes(n.tag))).toBe(false);
  expect(nodes.some(n=>n.textContent.includes("<img"))).toBe(true);
});
