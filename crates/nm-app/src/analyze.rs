//! Application analysis flow; no collector or credential secret access.
use crate::{AppError, Result};
use nm_analyze::{RuleConfig, SnapshotView};
use nm_core::{Finding, RuleId, SnapshotId};
use nm_store::{
    repo::{DeviceFilter, DeviceRepo, FindingsRepo, ProfileRepo, SiteRepo, SnapshotRepo},
    Db,
};
use std::path::Path;
/// Deterministic analysis and atomic replacement for a stored snapshot.
pub struct AnalyzeService<'a> {
    db: &'a Db,
    data_dir: &'a Path,
}
impl<'a> AnalyzeService<'a> {
    /// Bind an application database and its local rules.toml directory.
    pub fn new(db: &'a Db, data_dir: &'a Path) -> Self {
        Self { db, data_dir }
    }
    /// Evaluate a persisted snapshot; identical inputs preserve finding rows and IDs.
    pub fn run(&self, id: SnapshotId) -> Result<Vec<Finding>> {
        let snapshot = SnapshotRepo::new(self.db)
            .get(id)?
            .ok_or_else(|| AppError::Invalid("snapshot not found".into()))?;
        let devices = DeviceRepo::new(self.db).list(&DeviceFilter::default())?;
        let sites = SiteRepo::new(self.db).list()?;
        let profiles = ProfileRepo::new(self.db).list()?;
        let config =
            RuleConfig::load(&self.data_dir.join("rules.toml")).map_err(AppError::Invalid)?;
        let view = SnapshotView::new(&snapshot, &devices, &sites, &profiles);
        let findings = nm_analyze::runner::evaluate(&view, &config);
        FindingsRepo::new(self.db).replace(id, &findings)?;
        Ok(findings)
    }
    /// Persist enablement and recompute the selected snapshot immediately.
    pub fn set_enabled(
        &self,
        id: RuleId,
        enabled: bool,
        snapshot: Option<SnapshotId>,
    ) -> Result<()> {
        let path = self.data_dir.join("rules.toml");
        let mut cfg = RuleConfig::load(&path).map_err(AppError::Invalid)?;
        cfg.enabled.insert(id, enabled);
        cfg.save(&path).map_err(AppError::Invalid)?;
        if let Some(snapshot) = snapshot {
            self.run(snapshot)?;
        }
        Ok(())
    }
}
