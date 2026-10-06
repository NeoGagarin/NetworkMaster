use super::{from_json, id, json};
use crate::{Db, Result, StoreError};
use nm_core::{
    Device, DeviceFamily, DeviceId, EnrollmentSource, ManagementAddress, SiteId, Timestamp,
};
use rusqlite::{params, OptionalExtension, Row};

#[derive(Clone, Debug, Default)]
pub struct DeviceFilter {
    pub site: Option<SiteId>,
    pub family: Option<DeviceFamily>,
    pub enrolled: Option<bool>,
    pub source: Option<EnrollmentSource>,
}
pub struct DeviceRepo<'a> {
    db: &'a Db,
}
impl<'a> DeviceRepo<'a> {
    pub fn new(db: &'a Db) -> Self {
        Self { db }
    }
    pub fn insert(&self, device: &Device) -> Result<()> {
        let now = Timestamp::now().to_string();
        self.db.lock()?.execute("INSERT INTO devices (id,display_name,address,port,vendor,family,role,site_id,profile_id,source,enrolled,tags_json,created_at,updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?13)", params![
            device.id.to_string(), device.display_name, json(&device.management.host)?, device.management.port,
            json(&device.vendor)?, json(&device.family)?, json(&device.role)?, device.site.map(|v| v.to_string()),
            device.credential_profile.map(|v| v.to_string()), json(&device.source)?, device.enrolled, json(&device.tags)?, now])?;
        Ok(())
    }
    pub fn update(&self, device: &Device) -> Result<()> {
        let changed = self.db.lock()?.execute("UPDATE devices SET display_name=?2,address=?3,port=?4,vendor=?5,family=?6,role=?7,site_id=?8,profile_id=?9,source=?10,enrolled=?11,tags_json=?12,updated_at=?13 WHERE id=?1", params![
            device.id.to_string(), device.display_name, json(&device.management.host)?, device.management.port,
            json(&device.vendor)?, json(&device.family)?, json(&device.role)?, device.site.map(|v| v.to_string()),
            device.credential_profile.map(|v| v.to_string()), json(&device.source)?, device.enrolled, json(&device.tags)?, Timestamp::now().to_string()])?;
        if changed == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }
    pub fn get(&self, device_id: DeviceId) -> Result<Option<Device>> {
        Ok(self
            .db
            .lock()?
            .query_row(
                "SELECT * FROM devices WHERE id=?1",
                [device_id.to_string()],
                read,
            )
            .optional()?)
    }
    pub fn list(&self, filter: &DeviceFilter) -> Result<Vec<Device>> {
        let conn = self.db.lock()?;
        let mut stmt = conn.prepare("SELECT * FROM devices WHERE (?1 IS NULL OR site_id=?1) AND (?2 IS NULL OR family=?2) AND (?3 IS NULL OR enrolled=?3) AND (?4 IS NULL OR source=?4) ORDER BY id")?;
        let rows = stmt.query_map(
            params![
                filter.site.map(|v| v.to_string()),
                filter.family.map(|v| json(&v)).transpose()?,
                filter.enrolled,
                filter.source.map(|v| json(&v)).transpose()?
            ],
            read,
        )?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }
    pub fn set_enrolled(&self, device_id: DeviceId, enrolled: bool) -> Result<()> {
        let changed = self.db.lock()?.execute(
            "UPDATE devices SET enrolled=?2,updated_at=?3 WHERE id=?1",
            params![
                device_id.to_string(),
                enrolled,
                Timestamp::now().to_string()
            ],
        )?;
        if changed == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }
    pub fn delete(&self, device_id: DeviceId) -> Result<()> {
        if self
            .db
            .lock()?
            .execute("DELETE FROM devices WHERE id=?1", [device_id.to_string()])?
            == 0
        {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }
}
fn read(row: &Row<'_>) -> rusqlite::Result<Device> {
    Ok(Device {
        id: id(row.get("id")?)?,
        display_name: row.get("display_name")?,
        management: ManagementAddress {
            host: from_json(row.get("address")?)?,
            port: row.get("port")?,
        },
        vendor: from_json(row.get("vendor")?)?,
        family: from_json(row.get("family")?)?,
        role: from_json(row.get("role")?)?,
        site: row
            .get::<_, Option<String>>("site_id")?
            .map(id)
            .transpose()?,
        credential_profile: row
            .get::<_, Option<String>>("profile_id")?
            .map(id)
            .transpose()?,
        source: from_json(row.get("source")?)?,
        enrolled: row.get("enrolled")?,
        tags: from_json(row.get("tags_json")?)?,
    })
}
