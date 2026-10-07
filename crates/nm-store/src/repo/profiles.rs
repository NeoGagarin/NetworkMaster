use super::{from_json, id, json};
use crate::{Db, Result, StoreError};
use nm_core::{CredentialProfile, CredentialProfileId};
use rusqlite::{params, OptionalExtension, Row};
pub struct ProfileRepo<'a> {
    db: &'a Db,
}
impl<'a> ProfileRepo<'a> {
    pub fn new(db: &'a Db) -> Self {
        Self { db }
    }
    pub fn insert(&self, p: &CredentialProfile) -> Result<()> {
        self.db.lock()?.execute("INSERT INTO credential_profiles (id,name,kind,storage,scope_hint,is_vendor_default) VALUES (?1,?2,?3,?4,?5,?6)", params![p.id.to_string(),p.name,json(&p.kind)?,json(&p.storage)?,p.scope_hint,p.is_vendor_default])?;
        Ok(())
    }
    pub fn update(&self, p: &CredentialProfile) -> Result<()> {
        if self.db.lock()?.execute(
            "UPDATE credential_profiles SET name=?2,kind=?3,storage=?4,scope_hint=?5,is_vendor_default=?6 WHERE id=?1",
            params![
                p.id.to_string(),
                p.name,
                json(&p.kind)?,
                json(&p.storage)?,
                p.scope_hint,
                p.is_vendor_default
            ],
        )? == 0
        {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }
    pub fn get(&self, profile_id: CredentialProfileId) -> Result<Option<CredentialProfile>> {
        Ok(self
            .db
            .lock()?
            .query_row(
                "SELECT id,name,kind,storage,scope_hint,is_vendor_default FROM credential_profiles WHERE id=?1",
                [profile_id.to_string()],
                read,
            )
            .optional()?)
    }
    pub fn list(&self) -> Result<Vec<CredentialProfile>> {
        let conn = self.db.lock()?;
        let mut stmt = conn.prepare(
            "SELECT id,name,kind,storage,scope_hint,is_vendor_default FROM credential_profiles ORDER BY id",
        )?;
        let rows = stmt.query_map([], read)?.collect::<rusqlite::Result<_>>()?;
        Ok(rows)
    }
    pub fn delete(&self, profile_id: CredentialProfileId) -> Result<()> {
        if self.db.lock()?.execute(
            "DELETE FROM credential_profiles WHERE id=?1",
            [profile_id.to_string()],
        )? == 0
        {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }
}
fn read(r: &Row<'_>) -> rusqlite::Result<CredentialProfile> {
    Ok(CredentialProfile {
        id: id(r.get(0)?)?,
        name: r.get(1)?,
        kind: from_json(r.get(2)?)?,
        storage: from_json(r.get(3)?)?,
        scope_hint: r.get(4)?,
        is_vendor_default: r.get(5)?,
    })
}
