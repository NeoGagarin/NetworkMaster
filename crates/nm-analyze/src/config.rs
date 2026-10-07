//! Offline rule enablement and validated scalar threshold overrides.
use nm_core::RuleId;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, path::Path};
/// TOML `[enabled]` and `[thresholds.RULE-ID]` settings layered over catalog defaults.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RuleConfig {
    pub enabled: HashMap<RuleId, bool>,
    pub thresholds: HashMap<RuleId, HashMap<String, toml::Value>>,
}
impl RuleConfig {
    /// Read rules.toml. Missing files use defaults; invalid settings fail explicitly.
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(e.to_string()),
        };
        let c: Self = toml::from_str(&text).map_err(|e| e.to_string())?;
        c.validate()?;
        Ok(c)
    }
    /// Reject unknown IDs, keys, non-numeric values and invalid threshold domains.
    pub fn validate(&self) -> Result<(), String> {
        for id in self.enabled.keys().chain(self.thresholds.keys()) {
            let meta = crate::catalog::all()
                .iter()
                .find(|r| r.meta().id == *id)
                .map(|r| r.meta())
                .ok_or_else(|| format!("unknown rule {id}"))?;
            if let Some(values) = self.thresholds.get(id) {
                for (k, v) in values {
                    if !meta.thresholds.iter().any(|t| t.key == k) {
                        return Err(format!("unknown threshold {id}.{k}"));
                    }
                    let n = v
                        .as_float()
                        .or_else(|| {
                            v.as_integer()
                                .and_then(|n| i32::try_from(n).ok())
                                .map(f64::from)
                        })
                        .ok_or_else(|| format!("numeric threshold required: {id}.{k}"))?;
                    if !n.is_finite()
                        || (k.ends_with("dbm") && !(-150.0..=0.0).contains(&n))
                        || (!k.ends_with("dbm") && n < 0.0)
                        || (k.ends_with("pct") && n > 100.0)
                        || (k == "pool_ratio" && n > 1.0)
                    {
                        return Err(format!("threshold out of range: {id}.{k}"));
                    }
                }
            }
        }
        Ok(())
    }
    /// Persist in stable key order so toggles create reviewable changes.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        self.validate()?;
        let mut root = toml::map::Map::new();
        root.insert(
            "enabled".into(),
            toml::Value::Table(
                self.enabled
                    .iter()
                    .map(|(k, v)| (k.to_string(), toml::Value::Boolean(*v)))
                    .collect(),
            ),
        );
        root.insert(
            "thresholds".into(),
            toml::Value::Table(
                self.thresholds
                    .iter()
                    .map(|(id, v)| {
                        (
                            id.to_string(),
                            toml::Value::Table(
                                v.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
                            ),
                        )
                    })
                    .collect(),
            ),
        );
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p).map_err(|e| e.to_string())?;
        }
        std::fs::write(
            path,
            toml::to_string_pretty(&root).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())
    }
    /// Rules are enabled unless explicitly disabled.
    pub fn is_enabled(&self, id: &RuleId) -> bool {
        self.enabled.get(id).copied().unwrap_or(true)
    }
    /// Typed numeric override, otherwise the metadata default.
    pub fn get_f64(&self, id: &RuleId, key: &str) -> f64 {
        let v = self
            .thresholds
            .get(id)
            .and_then(|m| m.get(key))
            .or_else(|| {
                crate::catalog::all()
                    .iter()
                    .find(|r| r.meta().id == *id)?
                    .meta()
                    .thresholds
                    .iter()
                    .find(|t| t.key == key)
                    .map(|t| &t.default)
            })
            .expect("rule requests a registered threshold");
        v.as_float()
            .or_else(|| {
                v.as_integer()
                    .and_then(|n| i32::try_from(n).ok())
                    .map(f64::from)
            })
            .expect("validated numeric threshold")
    }
}
