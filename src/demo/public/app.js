let token, state, actionBusy=false, chatBusy=false, connectionLost=false;
const byId=id=>document.getElementById(id);
const node=(tag,text,className)=>{const n=document.createElement(tag);if(text!==undefined)n.textContent=text;if(className)n.className=className;return n;};
const when=at=>at?new Date(at).toLocaleTimeString():"time unavailable";
// Build rich text from DOM nodes; model output never enters an HTML parser.
function inlineMarkdown(parent,text){
  const tokens=/\*\*([^*\n]+)\*\*|`([^`\n]+)`|\*([^*\n]+)\*|\[([^\]\n]+)\]\(([^\s)]+)\)/g;
  let offset=0;
  for(const match of text.matchAll(tokens)){
    if(match.index>offset)parent.append(node("span",text.slice(offset,match.index)));
    if(match[1]){const strong=node("strong");inlineMarkdown(strong,match[1]);parent.append(strong);}
    else if(match[2])parent.append(node("code",match[2]));
    else if(match[3])parent.append(node("em",match[3]));
    else{
      let url;try{url=new URL(match[5]);}catch{}
      if(url&&["https:","http:"].includes(url.protocol)){
        const link=node("a",match[4]);link.href=url.href;link.rel="noopener noreferrer";link.target="_blank";parent.append(link);
      }else parent.append(node("span",match[0]));
    }
    offset=match.index+match[0].length;
  }
  if(offset<text.length)parent.append(node("span",text.slice(offset)));
}
function markdown(text){
  const root=node("div",undefined,"rich-text");let list=null,paragraph=[],fence=null;
  const flush=()=>{if(paragraph.length){const p=node("p");inlineMarkdown(p,paragraph.join(" "));root.append(p);paragraph=[];}};
  for(const line of String(text).replace(/\r\n/g,"\n").split("\n")){
    if(/^\s*```/.test(line)){flush();list=null;if(fence){root.append(node("pre",fence.join("\n")));fence=null;}else fence=[];continue;}
    if(fence){fence.push(line);continue;}
    if(!line.trim()){flush();list=null;continue;}
    const heading=line.match(/^\s*(#{1,6})\s+(.+)$/),item=line.match(/^\s*(?:([-+*])|\d+[.)])\s+(.+)$/),quote=line.match(/^>\s?(.*)$/);
    if(heading){flush();list=null;const h=node(heading[1].length>3?"h4":"h3");inlineMarkdown(h,heading[2]);root.append(h);}
    else if(item){flush();const kind=item[1]?"ul":"ol";if(!list||list.kind!==kind){const element=node(kind);root.append(element);list={kind,element};}const li=node("li");inlineMarkdown(li,item[2]);list.element.append(li);}
    else if(quote){flush();list=null;const block=node("blockquote");inlineMarkdown(block,quote[1]);root.append(block);}
    else{list=null;paragraph.push(line);}
  }
  flush();if(fence)root.append(node("pre",fence.join("\n")));return root;
}
function button(label,command,digest){const n=node("button",label,"secondary");n.disabled=actionBusy;n.addEventListener("click",()=>run(command,{digest}));return n;}
function renderRouter(r){
  const section=byId("router");section.replaceChildren();
  if(!r){section.append(node("p","Router integration is not connected."));return;}
  section.append(node("p",`Status: ${r.phase}.`,"note"));
  const controls=node("div",undefined,"controls");
  if(r.phase==="down")controls.append(button("Start router","router-prepare"));
  if(r.phase==="prepared")controls.append(button("Check password","router-attack"));
  if(r.phase==="attacked")controls.append(button("Ask Jev & Clef about the login","router-classify"),button("Review the password change","router-propose"));
  section.append(controls);
  for(const a of r.attempts)section.append(node("p",`${a.role}: ${a.outcome}, measured at ${when(a.finished_at)}.`));
  for(const j of r.judgments){const line=node("div",undefined,"judgment");line.append(node("span",`${j.model} (${j.inference_status})`),node("span",j.category));section.append(line);}
  if(r.proposal){section.append(node("h3","Change router password"),node("p",r.proposal.confirmation),node("p",`Approval ID: ${r.proposal.digest}. Expires ${when(r.proposal.expires_at)}.`,"digest"));
    if(r.phase==="proposed")section.append(button("Approve this exact password change","router-approve",r.proposal.digest));
    if(r.phase==="approved")section.append(button("Ask OpenAI to secure the router","router-execute",r.proposal.digest));
  }
  if(r.trace){const measured=node("section",undefined,"measured");measured.append(node("h3","Login verification"));for(const a of r.trace.attempts)measured.append(node("p",`${a.attempt}: ${a.outcome} at ${when(a.occurred_at)}.`));section.append(measured);}
  if(r.agent){section.append(node("h3","Agent response"),node("p",`Generated ${when(r.agent_at)}. ${r.agent.status}; ${r.agent.calls.length} tool calls.`));if(r.agent.explanation)section.append(markdown(r.agent.explanation.text),node("p",`Cited traces: ${r.agent.explanation.citations.join(", ")}`,"digest"));else section.append(node("p","No validated explanation available. Inspect the measured checks.","caution"));}
  if(r.phase!=="down")section.append(button("Stop router","router-cleanup"));
}
function render(s){
  state=s;
  // Polling must not replace the DOM while someone is selecting text to copy.
  if(globalThis.getSelection?.()?.toString())return;
  renderRouter(s.router);
  renderIncidents(s);renderChat(s);
  const logs=s.logs,rows=byId("captured-rows");rows.replaceChildren();
  byId("log-status").textContent=logs?(logs.status==="live"?"Live":logs.status==="starting"?"Connecting…":"Disconnected") : "Connecting…";
  for(const row of (logs?.rows??[]).slice(0,14)){
    const incident=(s.incidents?.incidents??[]).find(i=>i.source_ids?.includes(row.id));
    const tr=node("tr",undefined,incident?.category==="suspicious"?"indicator-row":"");
    const query=node("td",row.domain);if(incident?.category==="suspicious")query.append(node("small","Suspicious activity"));
    const result=["GRAVITY","DENYLIST","SPECIAL_DOMAIN"].includes(row.status)?"Blocked":row.reply==="IP"?(row.status==="CACHE"?"Resolved (cached)":"Resolved"):"Other response";
    tr.append(node("td",when(row.observed_at)),node("td",row.client),query,node("td",result));rows.append(tr);
  }
  if(!logs?.rows.length){const tr=node("tr"),td=node("td","Waiting for device logs…");td.colSpan=4;tr.append(td);rows.append(tr);}
  const activity=byId("activity-rows");activity.replaceChildren();
  for(const event of (logs?.events??[]).slice(0,16)){
    const li=node("li");li.append(node("time",when(event.at)),node("span",event.summary));
    if(event.evidence_refs.length)li.append(node("small",event.evidence_refs.join(", ")));activity.append(li);
  }
  const evidence=byId("evidence");evidence.replaceChildren();
  if(s.finding){evidence.append(node("h3","Flagged DNS activity"),node("p","update-check.cloudsyncapi.net was queried by 10.77.0.100."));}
  const judgments=byId("judgments");judgments.replaceChildren();
  for(const j of s.judgments){const line=node("div",undefined,"judgment"),label=node("span",j.model),value=node("span",j.category);label.append(node("small",j.provenance==="deterministic"?"Policy":`${j.provider}: ${j.inference_status}`));line.append(label,value);judgments.append(line);}
  const approval=byId("approval"),verification=byId("verification"),interpretation=byId("interpretation");approval.replaceChildren();verification.replaceChildren();interpretation.replaceChildren();
  const action=s.actions.filter(a=>a.proposal.evidence_revision===s.finding?.evidence_revision).at(-1);
  if(action){const p=action.proposal;approval.append(node("h3","Proposed response"),node("p",`Block ${p.domain} for client group ${p.group_id} until ${when(p.expires_at)}.`),node("p",`Approval ID: ${action.digest}`,"digest"),node("p",`Status: ${action.status}`));
    if(action.status==="proposed")approval.append(button("Approve block","approve",action.digest));
    if(action.status==="approved")approval.append(button("Apply with agent","execute",action.digest));
    if(["active","ambiguous","rollback-unverified"].includes(action.status))approval.append(button("Undo block","undo",action.digest));
    if(action.verification){const v=action.verification;verification.className="measured";verification.append(node("h3","Verification"),node("p",`update-check.cloudsyncapi.net: ${v.target}. wikipedia.org: ${v.benign}.`),node("p",`Checked ${when(v.checked_at)}.`));}
  }
  if(s.agent){interpretation.append(node("h3","Agent response"),node("p",`OpenAI · ${when(s.agent_at)} · ${s.agent.status} · ${s.agent.calls.length} tool calls`));
    if(s.agent.explanation){interpretation.append(markdown(s.agent.explanation.text),node("p",`Cited traces: ${s.agent.explanation.citations.join(", ")}`,"digest"));}
    else interpretation.append(node("p","The agent could not finish its explanation. See verification above.","caution"));
  }
  const timeline=byId("timeline");timeline.replaceChildren();for(const t of s.traces.slice(-8)){const li=node("li",t.summary);li.append(node("time",when(t.at)));timeline.append(li);}
  const guidance=byId("guidance");
  const openGuidance=[...guidance.querySelectorAll("details")].map(d=>d.open);
  guidance.replaceChildren();
  if(s.guidance){guidance.append(node("h3","Reference guidance"),node("p",`Senso · ${s.guidance.status}`));
    for(const [index,result] of s.guidance.results.entries()){
      if(result.status!=="ok"){guidance.append(node("p",`Reference unavailable: ${result.reason}`,"caution"));continue;}
      const detail=node("details"),label=result.topic==="dns-deny-limits"?"DNS protection":"Understanding the evidence";detail.open=!!openGuidance[index];
      detail.append(node("summary",label));
      for(const passage of result.passages)detail.append(markdown(passage.text));
      detail.append(node("p",`Source document: ${result.document.title}. Senso content ID: ${result.citations.join(", ")}. Retrieved at ${when(s.guidance.completed_at)}.`,"digest"));guidance.append(detail);
    }
  }
  const sponsors=byId("sponsors");sponsors.replaceChildren();
  if(s.sponsors){const report=s.sponsors.report;
    for(const backend of report.sponsors)sponsors.append(node("p",`${backend.sponsor}: ${backend.health}. Serving from ${backend.serving_backend}. ${backend.version?`Version ${backend.version}.`:""}`));
    if(s.sponsors.evidence){const current=!s.sponsors.error&&s.finding&&s.sponsors.evidence_revision===s.finding.evidence_revision;sponsors.append(node("p",`${s.sponsors.evidence.evidence.lookups} lookup observations returned by ${s.sponsors.evidence.backend}. ${current?"Matches this incident’s evidence revision.":"Retained audit result; not confirmed for the current incident."}`));}
    if(s.sponsors.actions)sponsors.append(node("p",`${s.sponsors.actions.value.length} action audit projections read from ${s.sponsors.actions.backend}; last checked ${when(s.sponsors.checked_at)}.`));
    const scan=report.security_scan;sponsors.append(node("p",scan?`Semgrep ${scan.version||"version unavailable"}: ${scan.status}; ${scan.scanned_files} files, ${scan.findings.length} findings. Revision ${scan.revision?.slice(0,12)||"unknown"}${scan.worktree_dirty?" with uncommitted changes":""}.`:"Semgrep has not run for this session."));
    if(s.sponsors.error)sponsors.append(node("p",s.sponsors.error,"caution"));
  }else sponsors.append(node("p","Sponsor stores are not configured for this session."));
  byId("raw").textContent=JSON.stringify(s,null,2);
  document.querySelectorAll("button[data-command]").forEach(n=>n.disabled=actionBusy);
}
async function session(){const response=await fetch("/api/session");if(!response.ok)throw new Error("Local session unavailable");token=(await response.json()).token;}
async function refresh(){const response=await fetch("/api/state");if(!response.ok)throw new Error("State unavailable");render(await response.json());if(connectionLost){connectionLost=false;byId("message").textContent="Connected.";}}
async function run(command,input={}){const isChat=command==="chat";if(isChat?chatBusy:actionBusy)return;if(isChat)chatBusy=true;else actionBusy=true;if(state)render(state);byId("message").textContent="Working…";
  try{await session();const response=await fetch(`/api/${command}`,{method:"POST",headers:{"Content-Type":"application/json","X-Hedgerow-CSRF":token},body:JSON.stringify(input)});const result=await response.json();if(!response.ok)throw new Error(result.error||"Operation unavailable");render(result);byId("message").textContent="Done.";}
  catch(error){byId("message").textContent=error.message;await refresh().catch(()=>{});}
  finally{if(isChat)chatBusy=false;else actionBusy=false;if(state)render(state);}}
document.querySelectorAll("[data-command]").forEach(n=>n.addEventListener("click",()=>run(n.dataset.command)));
  (async()=>{try{await session();await refresh();setInterval(()=>{void refresh().catch(()=>{connectionLost=true;byId("message").textContent="Disconnected. Reconnecting…";});},1500);}catch(error){byId("message").textContent=error.message;}})();

function renderIncidents(s){
  const root=byId("incident-groups");root.replaceChildren();
  for(const item of (s.incidents?.incidents??[]).slice(0,4)){
    const card=node("button",undefined,"incident-group "+(item.category==="suspicious"?"flagged":""));
    card.type="button";card.append(node("strong",item.category==="suspicious"?"Flagged DNS activity":item.status==="classifying"?"Analyzing logs…":"DNS activity"));
    card.append(node("small",`${item.source_ids?.length??0} log rows · ${(item.judgments??[]).map(j=>j.model.includes("jev")?"Jev: "+j.category:"Clef: "+j.category).join(" · ")||item.status}`));
    card.addEventListener("click",()=>{byId("chat-input").value=`Explain incident ${item.id}`;byId("chat-input").focus();});
    root.append(card);
  }
}
function renderChat(s){
  const root=byId("chat-messages"),messages=s.chat?.messages??[];
  const signature=JSON.stringify(messages);
  if(root.dataset.signature!==signature){root.dataset.signature=signature;root.replaceChildren();
    for(const m of messages){const line=node("div",undefined,"chat-message "+m.role);line.append(node("small",m.role==="user"?"You":"Hedgerow"),m.role==="assistant"?markdown(m.content):node("p",m.content));root.append(line);}
    root.scrollTop=root.scrollHeight;
  }
  byId("chat-input").disabled=chatBusy;
  if(s.chat?.error)byId("message").textContent=s.chat.error;
}
byId("chat-form").addEventListener("submit",async e=>{e.preventDefault();const field=byId("chat-input"),message=field.value.trim();if(!message||chatBusy)return;field.value="";await run("chat",{message});});
