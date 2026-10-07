//! Atomic replacement and filtered queries for persisted snapshot findings.
use super::{from_json, id, json};
use crate::{Db, Result};
use nm_core::{Category, DeviceId, Finding, RuleId, Severity, SnapshotId};
use rusqlite::params;
/// Query dimensions; unset fields match all persisted findings.
#[derive(Clone, Debug, Default)]
pub struct FindingFilter {
    pub snapshot: Option<SnapshotId>,
    pub severity_min: Option<Severity>,
    pub category: Option<Category>,
    pub device: Option<DeviceId>,
    pub rule: Option<RuleId>,
}
/// Snapshot findings repository. A replacement commits all rows together.
pub struct FindingsRepo<'a> {
    db: &'a Db,
}
impl<'a> FindingsRepo<'a> {
    /// Use the existing application database.
    pub fn new(db: &'a Db) -> Self {
        Self { db }
    }
    /// Replace one snapshot's findings atomically; stable IDs make this idempotent.
    pub fn replace(&self, snapshot: SnapshotId, findings: &[Finding]) -> Result<()> {
        let mut conn = self.db.lock()?;
        let tx = conn.transaction()?;
        tx.execute(
            "DELETE FROM findings WHERE snapshot_id=?1",
            [snapshot.to_string()],
        )?;
        for f in findings {
            tx.execute(
                "INSERT INTO findings VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                params![
                    f.id.to_string(),
                    snapshot.to_string(),
                    f.rule_id.as_str(),
                    f.severity as u8,
                    json(&f.category)?,
                    f.title,
                    json(&f.evidence)?,
                    json(&f.devices)?,
                    json(&f.confidence)?,
                    f.explanation
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }
    /// Query observations in severity, rule and device order.
    pub fn query(&self, filter: &FindingFilter) -> Result<Vec<Finding>> {
        let conn = self.db.lock()?;
        let mut stmt=conn.prepare("SELECT id,rule_id,severity,category,title,evidence_json,devices_json,confidence,explanation FROM findings WHERE (?1 IS NULL OR snapshot_id=?1) AND (?2 IS NULL OR severity>=?2) AND (?3 IS NULL OR category=?3) AND (?4 IS NULL OR rule_id=?4) AND (?5 IS NULL OR EXISTS (SELECT 1 FROM json_each(findings.devices_json) WHERE value=?5)) ORDER BY severity DESC,rule_id,id")?;
        let mut out = stmt
            .query_map(
                params![
                    filter.snapshot.map(|s| s.to_string()),
                    filter.severity_min.map(|s| s as u8),
                    filter.category.map(|c| json(&c)).transpose()?,
                    filter.rule.as_ref().map(RuleId::as_str),
                    filter.device.map(|d| d.to_string())
                ],
                read,
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        out.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| a.rule_id.as_str().cmp(b.rule_id.as_str()))
                .then_with(|| a.devices.cmp(&b.devices))
                .then_with(|| a.id.cmp(&b.id))
        });
        Ok(out)
    }
}

/// Decode the shared findings column order, also used by `SnapshotRepo`.
pub(crate) fn read(r: &rusqlite::Row<'_>) -> rusqlite::Result<Finding> {
    let severity = match r.get::<_, u8>(2)? {
        0 => Severity::Info,
        1 => Severity::Low,
        2 => Severity::Medium,
        3 => Severity::High,
        4 => Severity::Critical,
        _ => return Err(rusqlite::Error::InvalidQuery),
    };
    Ok(Finding {
        id: id(r.get(0)?)?,
        rule_id: id(r.get(1)?)?,
        severity,
        category: from_json(r.get(3)?)?,
        title: r.get(4)?,
        evidence: from_json(r.get(5)?)?,
        devices: from_json(r.get(6)?)?,
        confidence: from_json(r.get(7)?)?,
        explanation: r.get(8)?,
    })
}
