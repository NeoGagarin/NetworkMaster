use super::{from_json, id, json};
use crate::{Db, Result, StoreError};
use nm_core::{DeviceId, DeviceResult, Finding, RawArtifact, Snapshot, SnapshotId, Timestamp};
use rusqlite::{params, OptionalExtension};
use sha2::{Digest, Sha256};

pub struct SnapshotRepo<'a> {
    db: &'a Db,
}
impl<'a> SnapshotRepo<'a> {
    pub fn new(db: &'a Db) -> Self {
        Self { db }
    }
    pub fn create(&self, snapshot: &Snapshot, inventory_hash: &str, notes: &str) -> Result<()> {
        self.db.lock()?.execute(
            "INSERT INTO snapshots VALUES (?1,?2,?3,?4,?5)",
            params![
                snapshot.id.to_string(),
                snapshot.started_at.to_string(),
                snapshot.finished_at.map(|v| v.to_string()),
                inventory_hash,
                notes
            ],
        )?;
        Ok(())
    }
    pub fn finish(&self, snapshot_id: SnapshotId, finished_at: Timestamp) -> Result<()> {
        if self.db.lock()?.execute(
            "UPDATE snapshots SET finished_at=?2 WHERE id=?1",
            params![snapshot_id.to_string(), finished_at.to_string()],
        )? == 0
        {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }
    pub fn get(&self, snapshot_id: SnapshotId) -> Result<Option<Snapshot>> {
        // Each lock is released before loading the child records.
        let head = self
            .db
            .lock()?
            .query_row(
                "SELECT started_at,finished_at FROM snapshots WHERE id=?1",
                [snapshot_id.to_string()],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?)),
            )
            .optional()?;
        let Some((started, finished)) = head else {
            return Ok(None);
        };
        let conn = self.db.lock()?;
        let mut stmt = conn.prepare("SELECT device_id,outcome,facts_json,coverage_json FROM device_results WHERE snapshot_id=?1 ORDER BY device_id")?;
        let mut device_results = stmt
            .query_map([snapshot_id.to_string()], |r| {
                Ok(DeviceResult {
                    device_id: id(r.get(0)?)?,
                    outcome: from_json(r.get(1)?)?,
                    facts: from_json(r.get(2)?)?,
                    raw: vec![],
                    coverage: from_json(r.get(3)?)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for result in &mut device_results {
            let mut raw = conn.prepare("SELECT kind,name,bytes,sha256,redacted FROM raw_artifacts WHERE snapshot_id=?1 AND device_id=?2 ORDER BY name")?;
            result.raw = raw
                .query_map(
                    [snapshot_id.to_string(), result.device_id.to_string()],
                    |r| {
                        let hash: Vec<u8> = r.get(3)?;
                        let sha256 = hash.try_into().map_err(|_| rusqlite::Error::InvalidQuery)?;
                        Ok(RawArtifact {
                            kind: from_json(r.get(0)?)?,
                            name: r.get(1)?,
                            bytes: r.get(2)?,
                            sha256,
                            redacted: r.get(4)?,
                        })
                    },
                )?
                .collect::<rusqlite::Result<_>>()?;
        }
        let mut stmt = conn.prepare("SELECT id,rule_id,severity,category,title,evidence_json,devices_json,confidence,explanation FROM findings WHERE snapshot_id=?1")?;
        let mut findings: Vec<nm_core::Finding> = stmt
            .query_map([snapshot_id.to_string()], super::findings::read)?
            .collect::<rusqlite::Result<_>>()?;
        // Finding ids hash the device ids, so ordering by id would make the
        // display order depend on inventory ids. Use the runner's order instead.
        nm_core::Finding::sort_canonical(&mut findings);
        let started_at = serde_json::from_value(serde_json::Value::String(started))?;
        let finished_at = finished
            .map(|s| serde_json::from_value(serde_json::Value::String(s)))
            .transpose()?;
        Ok(Some(Snapshot {
            id: snapshot_id,
            started_at,
            finished_at,
            device_results,
            findings,
        }))
    }
    pub fn list(&self) -> Result<Vec<Snapshot>> {
        let ids: Vec<SnapshotId> = {
            let conn = self.db.lock()?;
            let mut stmt =
                conn.prepare("SELECT id FROM snapshots ORDER BY started_at DESC,id DESC")?;
            let rows = stmt
                .query_map([], |r| id(r.get(0)?))?
                .collect::<rusqlite::Result<_>>()?;
            rows
        };
        ids.into_iter()
            .map(|sid| self.get(sid)?.ok_or(StoreError::NotFound))
            .collect()
    }
    pub fn latest_for_inventory_hash(&self, hash: &str) -> Result<Option<Snapshot>> {
        let sid: Option<SnapshotId> = self.db.lock()?.query_row("SELECT id FROM snapshots WHERE inventory_hash=?1 AND finished_at IS NOT NULL ORDER BY started_at DESC,id DESC LIMIT 1", [hash], |r| id(r.get(0)?)).optional()?;
        sid.map(|sid| self.get(sid))
            .transpose()
            .map(Option::flatten)
    }
    pub fn insert_device_result(
        &self,
        snapshot_id: SnapshotId,
        result: &DeviceResult,
    ) -> Result<()> {
        // Raw artifacts are inserted explicitly so the redaction boundary is never bypassed.
        self.db.lock()?.execute(
            "INSERT INTO device_results VALUES (?1,?2,?3,?4,?5)",
            params![
                snapshot_id.to_string(),
                result.device_id.to_string(),
                json(&result.outcome)?,
                json(&result.facts)?,
                json(&result.coverage)?
            ],
        )?;
        Ok(())
    }
    pub fn insert_raw_artifact(
        &self,
        snapshot_id: SnapshotId,
        device_id: DeviceId,
        raw: &RawArtifact,
    ) -> Result<()> {
        if !raw.redacted {
            return Err(StoreError::UnredactedArtifact);
        }
        if <[u8; 32]>::from(Sha256::digest(&raw.bytes)) != raw.sha256 {
            return Err(StoreError::ArtifactHash);
        }
        self.db.lock()?.execute(
            "INSERT INTO raw_artifacts VALUES (?1,?2,?3,?4,?5,?6,1)",
            params![
                snapshot_id.to_string(),
                device_id.to_string(),
                json(&raw.kind)?,
                raw.name,
                raw.bytes,
                raw.sha256.as_slice()
            ],
        )?;
        Ok(())
    }
    pub fn insert_findings(&self, snapshot_id: SnapshotId, findings: &[Finding]) -> Result<()> {
        let mut conn = self.db.lock()?;
        let tx = conn.transaction()?;
        for f in findings {
            tx.execute(
                "INSERT INTO findings VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                params![
                    f.id.to_string(),
                    snapshot_id.to_string(),
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
}
