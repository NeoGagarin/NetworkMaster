use crate::{DeviceId, FindingId};
use serde::{de::Error, Deserialize, Deserializer, Serialize};
use std::{fmt, str::FromStr};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub id: FindingId,
    pub rule_id: RuleId,
    pub severity: Severity,
    pub category: Category,
    pub devices: Vec<DeviceId>,
    pub title: String,
    pub evidence: Vec<Evidence>,
    pub explanation: String,
    pub confidence: Confidence,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Category {
    Security,
    Performance,
    Reliability,
    Capacity,
    Hygiene,
    RfHealth,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Confidence {
    Certain,
    Likely,
    Heuristic,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    pub device_id: DeviceId,
    pub metric_path: String,
    pub observed: serde_json::Value,
    pub threshold: Option<serde_json::Value>,
}
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct RuleId(String);
impl RuleId {
    pub fn new(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        let parts: Vec<_> = value.split('-').collect();
        if parts.len() == 3
            && matches!(parts[0], "UBNT" | "GEN")
            && matches!(parts[1], "SEC" | "PERF" | "REL" | "CAP" | "HYG" | "RF")
            && parts[2].len() == 3
            && parts[2].bytes().all(|b| b.is_ascii_digit())
        {
            Ok(Self(value))
        } else {
            Err(format!("invalid rule ID: {value}"))
        }
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl fmt::Display for RuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl FromStr for RuleId {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}
impl<'de> Deserialize<'de> for RuleId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(d)?).map_err(D::Error::custom)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn severity_and_rule_validation() {
        assert!(Severity::Info < Severity::Low && Severity::High < Severity::Critical);
        assert!(RuleId::new("UBNT-SEC-001").is_ok());
        for invalid in ["UBNT-FOO-001", "GEN-SEC-01", "GEN-SEC-0001", "GEN-SEC-abc"] {
            assert!(RuleId::new(invalid).is_err());
            assert!(serde_json::from_value::<RuleId>(serde_json::json!(invalid)).is_err());
        }
    }
}
