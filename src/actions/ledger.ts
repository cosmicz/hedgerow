import { Database } from "bun:sqlite";
import type { ActionRecord, ActionStatus, Proposal, Verification } from "./types";

type Row = { digest: string; proposal: string; status: ActionStatus; approved_by: string | null;
  verification: string | null; detail: string };
export interface ActionEvent {
  seq: number; digest: string; status: ActionStatus; detail: string;
  at: number | null; verification: Verification | null;
}

/** Local durable authority. Sponsor stores may mirror this journal, never authorize it. */
export class SqliteLedger {
  private db: Database;
  constructor(path: string, private readonly now: () => number = Date.now) {
    this.db = new Database(path, { create: true });
    this.db.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;");
    this.db.exec(`CREATE TABLE IF NOT EXISTS actions (
      digest TEXT PRIMARY KEY, proposal TEXT NOT NULL, status TEXT NOT NULL,
      approved_by TEXT, verification TEXT, detail TEXT NOT NULL DEFAULT ''
    ); CREATE TABLE IF NOT EXISTS action_events (
      seq INTEGER PRIMARY KEY AUTOINCREMENT, digest TEXT NOT NULL,
      status TEXT NOT NULL, detail TEXT NOT NULL
    )`);
    // Additive migration preserves old events. Missing historical evidence is
    // unknown, never backfilled with a fabricated current timestamp.
    const columns = this.db.query("PRAGMA table_info(action_events)").all() as {name:string}[];
    if (!columns.some(x=>x.name === "at")) this.db.exec("ALTER TABLE action_events ADD COLUMN at INTEGER");
    if (!columns.some(x=>x.name === "verification")) this.db.exec("ALTER TABLE action_events ADD COLUMN verification TEXT");
    // Pi-hole owns one exact domain entry across groups. Hold the resource
    // across ambiguous states too, so a second proposal cannot overwrite it.
    this.db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS action_resource_lock ON actions(
      json_extract(proposal, '$.resolver_id'), json_extract(proposal, '$.network_scope'),
      json_extract(proposal, '$.domain')
    ) WHERE status IN ('executing', 'active', 'ambiguous', 'undoing', 'rollback-unverified')`);
  }
  put(digest: string, proposal: Proposal): ActionRecord {
    this.db.query("INSERT OR IGNORE INTO actions(digest, proposal, status) VALUES (?, ?, 'proposed')")
      .run(digest, JSON.stringify(proposal));
    return this.get(digest);
  }
  get(digest: string): ActionRecord {
    const row = this.db.query("SELECT * FROM actions WHERE digest=?").get(digest) as Row | null;
    if (!row) throw new Error("Unknown proposal");
    return { ...row, proposal: JSON.parse(row.proposal), verification: row.verification ? JSON.parse(row.verification) : null };
  }
  list(): ActionRecord[] {
    return (this.db.query("SELECT digest FROM actions ORDER BY rowid").all() as {digest: string}[])
      .map(x => this.get(x.digest));
  }
  history(digest: string): ActionEvent[] {
    const rows = this.db.query("SELECT * FROM action_events WHERE digest=? ORDER BY seq").all(digest) as
      (Omit<ActionEvent,"verification"> & {verification:string|null})[];
    return rows.map(row=>({...row,verification:row.verification ? JSON.parse(row.verification) : null}));
  }
  transition(digest: string, from: ActionStatus[], to: ActionStatus,
    detail = "", verification: Verification | null = null, approver: string | null = null): boolean {
    return this.db.transaction(() => {
      const placeholders = from.map(() => "?").join(",");
      const at = this.now();
      if (!Number.isSafeInteger(at) || at < 0) throw new Error("Invalid journal clock");
      const change = this.db.query(`UPDATE actions SET status=?, detail=?, verification=COALESCE(?, verification),
        approved_by=COALESCE(?, approved_by) WHERE digest=? AND status IN (${placeholders})`)
        .run(to, detail, verification ? JSON.stringify(verification) : null, approver, digest, ...from);
      if (change.changes !== 1) return false;
      this.db.query("INSERT INTO action_events(digest, status, detail, at, verification) VALUES (?, ?, ?, ?, ?)")
        .run(digest, to, detail, at, verification ? JSON.stringify(verification) : null);
      return true;
    })();
  }
  close() { this.db.close(); }
}
