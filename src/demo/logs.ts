import { Database } from "bun:sqlite";

export interface CapturedQuery {
  id: string; observed_at: number; captured_at: number; domain: string;
  client: string; type: "A"; status: string; reply: string; indicator: boolean;
}
/** Closed display projection of real Pi-hole /queries rows; never arbitrary log text. */
export function projectQueryLogs(data: unknown, now: number): CapturedQuery[] {
  const rows=(data as any)?.queries;
  if(!Array.isArray(rows)||rows.length>100)throw Error("Query log unavailable");
  return rows.flatMap(row=>{
    if(!row||!Number.isSafeInteger(row.id)||row.id<0||!Number.isFinite(row.time))throw Error("Invalid query log");
    const at=Math.round(row.time*1000);
    if(row.client?.ip!=="10.77.0.100"||!["flagged.lab.test","benign.lab.test"].includes(row.domain)||row.type!=="A"||at>now||at<now-60_000)return [];
    return [{id:`pihole:query:${row.id}`,observed_at:at,captured_at:now,domain:row.domain,client:"10.77.0.100",type:"A" as const,
      status:["CACHE","FORWARDED","GRAVITY","DENYLIST","SPECIAL_DOMAIN"].includes(row.status)?row.status:"OTHER",
      reply:row.reply?.type==="IP"?"IP":"OTHER",indicator:row.domain==="flagged.lab.test"}];
  });
}

/** Local retained history, separate from action authority. Polling is read-only. */
export class CapturedLogs {
  private db: Database;
  private polling=false;
  private status="starting";
  private checkedAt:number|null=null;
  constructor(path:string,private read:()=>Promise<unknown>,private now=Date.now){
    this.db=new Database(path);
    this.db.exec("CREATE TABLE IF NOT EXISTS captured_queries (id TEXT PRIMARY KEY, at INTEGER NOT NULL, body TEXT NOT NULL); CREATE TABLE IF NOT EXISTS activity (seq INTEGER PRIMARY KEY AUTOINCREMENT, body TEXT NOT NULL)");
  }
  async poll(){
    if(this.polling)return;
    this.polling=true;
    try{
      const rows=projectQueryLogs(await this.read(),this.now());
      const insert=this.db.query("INSERT OR IGNORE INTO captured_queries VALUES (?, ?, ?)");
      for(const row of rows)insert.run(row.id,row.observed_at,JSON.stringify(row));
      this.db.exec("DELETE FROM captured_queries WHERE id NOT IN (SELECT id FROM captured_queries ORDER BY at DESC LIMIT 200)");
      this.checkedAt=this.now();this.status="live";
    }catch{this.status="unavailable";}finally{this.polling=false;}
  }
  event(kind:string,summary:string,evidence_refs:string[]=[]){
    this.db.query("INSERT INTO activity(body) VALUES (?)").run(JSON.stringify({at:this.now(),kind,summary,evidence_refs}));
    this.db.exec("DELETE FROM activity WHERE seq NOT IN (SELECT seq FROM activity ORDER BY seq DESC LIMIT 200)");
  }
  snapshot(){
    const parse=(row:any)=>JSON.parse(row.body);
    return {status:this.status==="live"&&this.checkedAt!==null&&this.now()-this.checkedAt>10_000?"stale":this.status,checked_at:this.checkedAt,scope:"Owned lab client 10.77.0.100; two test domains; VM-live",
      rows:this.db.query("SELECT body FROM captured_queries ORDER BY at DESC LIMIT 80").all().map(parse) as CapturedQuery[],
      events:this.db.query("SELECT body FROM activity ORDER BY seq DESC LIMIT 80").all().map(parse) as {at:number;kind:string;summary:string;evidence_refs:string[]}[]};
  }
  close(){this.db.close();}
}
