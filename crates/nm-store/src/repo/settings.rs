use crate::{Db, Result};
use rusqlite::{params, OptionalExtension};
use serde::{de::DeserializeOwned, Serialize};
pub struct SettingsRepo<'a> {
    db: &'a Db,
}
impl<'a> SettingsRepo<'a> {
    pub fn new(db: &'a Db) -> Self {
        Self { db }
    }
    pub fn get<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>> {
        let value: Option<String> = self
            .db
            .lock()?
            .query_row("SELECT value_json FROM settings WHERE key=?1", [key], |r| {
                r.get(0)
            })
            .optional()?;
        Ok(value.map(|v| serde_json::from_str(&v)).transpose()?)
    }
    pub fn set<T: Serialize>(&self, key: &str, value: &T) -> Result<()> {
        self.db.lock()?.execute("INSERT INTO settings VALUES (?1,?2) ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json", params![key, super::json(value)?])?;
        Ok(())
    }
    pub fn delete(&self, key: &str) -> Result<()> {
        self.db
            .lock()?
            .execute("DELETE FROM settings WHERE key=?1", [key])?;
        Ok(())
    }
}
