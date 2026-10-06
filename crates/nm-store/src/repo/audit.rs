use super::{from_json, json};
use crate::{Db, Result};
use nm_core::{AuditEvent, Timestamp};
use rusqlite::{params, Row};
pub struct AuditRepo<'a> {
    db: &'a Db,
}
impl<'a> AuditRepo<'a> {
    pub fn new(db: &'a Db) -> Self {
        Self { db }
    }
    pub fn append(&self, event: &AuditEvent) -> Result<()> {
        self.db.lock()?.execute("INSERT INTO audit_log (ts,actor,action,target,detail_json,bytes_out,bytes_in) VALUES (?1,?2,?3,?4,?5,?6,?7)", params![event.ts.to_string(),json(&event.actor)?,json(&event.action)?,event.target,json(&event.detail)?,event.bytes_out,event.bytes_in])?;
        Ok(())
    }
    pub fn tail(&self, count: usize) -> Result<Vec<AuditEvent>> {
        let conn = self.db.lock()?;
        let mut stmt = conn.prepare("SELECT * FROM audit_log ORDER BY seq DESC LIMIT ?1")?;
        let rows = stmt
            .query_map([i64::try_from(count).unwrap_or(i64::MAX)], read)?
            .collect::<rusqlite::Result<_>>()?;
        Ok(rows)
    }
    pub fn query(&self, start: Timestamp, end: Timestamp) -> Result<Vec<AuditEvent>> {
        let conn = self.db.lock()?;
        let mut stmt = conn.prepare("SELECT * FROM audit_log WHERE julianday(ts)>=julianday(?1) AND julianday(ts)<=julianday(?2) ORDER BY seq")?;
        let rows = stmt
            .query_map([start.to_string(), end.to_string()], read)?
            .collect::<rusqlite::Result<_>>()?;
        Ok(rows)
    }
}
fn read(r: &Row<'_>) -> rusqlite::Result<AuditEvent> {
    Ok(AuditEvent {
        ts: from_json(format!("\"{}\"", r.get::<_, String>("ts")?))?,
        actor: from_json(r.get("actor")?)?,
        action: from_json(r.get("action")?)?,
        target: r.get("target")?,
        detail: from_json(r.get("detail_json")?)?,
        bytes_out: r.get("bytes_out")?,
        bytes_in: r.get("bytes_in")?,
    })
}
