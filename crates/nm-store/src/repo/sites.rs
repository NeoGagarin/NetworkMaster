use super::id;
use crate::{Db, Result, StoreError};
use nm_core::{Site, SiteId};
use rusqlite::{params, OptionalExtension, Row};
pub struct SiteRepo<'a> {
    db: &'a Db,
}
impl<'a> SiteRepo<'a> {
    pub fn new(db: &'a Db) -> Self {
        Self { db }
    }
    pub fn insert(&self, site: &Site) -> Result<()> {
        self.db.lock()?.execute(
            "INSERT INTO sites (id,name,notes,max_distance_m) VALUES (?1,?2,?3,?4)",
            params![
                site.id.to_string(),
                site.name,
                site.notes,
                site.max_distance_m
            ],
        )?;
        Ok(())
    }
    pub fn update(&self, site: &Site) -> Result<()> {
        if self.db.lock()?.execute(
            "UPDATE sites SET name=?2,notes=?3,max_distance_m=?4 WHERE id=?1",
            params![
                site.id.to_string(),
                site.name,
                site.notes,
                site.max_distance_m
            ],
        )? == 0
        {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }
    pub fn get(&self, site_id: SiteId) -> Result<Option<Site>> {
        Ok(self
            .db
            .lock()?
            .query_row(
                "SELECT * FROM sites WHERE id=?1",
                [site_id.to_string()],
                read,
            )
            .optional()?)
    }
    pub fn list(&self) -> Result<Vec<Site>> {
        let conn = self.db.lock()?;
        let mut stmt = conn.prepare("SELECT * FROM sites ORDER BY name,id")?;
        let rows = stmt.query_map([], read)?.collect::<rusqlite::Result<_>>()?;
        Ok(rows)
    }
    pub fn delete(&self, site_id: SiteId) -> Result<()> {
        if self
            .db
            .lock()?
            .execute("DELETE FROM sites WHERE id=?1", [site_id.to_string()])?
            == 0
        {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }
}
fn read(r: &Row<'_>) -> rusqlite::Result<Site> {
    Ok(Site {
        id: id(r.get(0)?)?,
        name: r.get(1)?,
        notes: r.get(2)?,
        max_distance_m: r.get(3)?,
    })
}
