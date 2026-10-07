use crate::{Db, Result};
use nm_core::{DeviceId, Timestamp};
use rusqlite::params;

pub enum HostKeyCheck {
    FirstSeen,
    Matching,
    Changed { expected: String },
}
pub struct HostKeyStore {
    db: Db,
}
impl HostKeyStore {
    pub fn new(db: Db) -> Self {
        Self { db }
    }
    /// The check and initial insert share one transaction; concurrent first use
    /// can never replace a previously accepted fingerprint.
    pub fn check(
        &self,
        device: DeviceId,
        algorithm: &str,
        fingerprint: &str,
    ) -> Result<HostKeyCheck> {
        let mut conn = self.db.lock()?;
        let tx = conn.transaction()?;
        let keys: Vec<(String, String)> = {
            let mut stmt =
                tx.prepare("SELECT algorithm,fingerprint FROM ssh_host_keys WHERE device_id=?1")?;
            let rows = stmt
                .query_map([device.to_string()], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<rusqlite::Result<_>>()?;
            rows
        };
        let now = Timestamp::now().to_string();
        let check = if keys.is_empty() {
            tx.execute(
                "INSERT INTO ssh_host_keys VALUES (?1,?2,?3,?4,?4)",
                params![device.to_string(), algorithm, fingerprint, now],
            )?;
            HostKeyCheck::FirstSeen
        } else if keys.iter().any(|(a, f)| a == algorithm && f == fingerprint) {
            tx.execute(
                "UPDATE ssh_host_keys SET last_seen=?3 WHERE device_id=?1 AND algorithm=?2",
                params![device.to_string(), algorithm, now],
            )?;
            HostKeyCheck::Matching
        } else {
            HostKeyCheck::Changed {
                expected: keys[0].1.clone(),
            }
        };
        tx.commit()?;
        Ok(check)
    }
}
