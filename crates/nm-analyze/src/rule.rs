//! Rule contracts and catalog metadata.
use crate::{RuleConfig, SnapshotView};
use nm_core::{Category, Confidence, DeviceFamily, Finding, RuleId, Severity};
/// Configurable scalar with an explicit documented default.
#[derive(Clone, Debug, serde::Serialize)]
pub struct ThresholdSpec {
    pub key: &'static str,
    pub default: toml::Value,
    pub description: &'static str,
}
/// Explanation and applicability shared by evaluation, CLI and documentation.
#[derive(Debug, serde::Serialize)]
pub struct RuleMeta {
    pub id: RuleId,
    pub title: &'static str,
    pub category: Category,
    pub default_severity: Severity,
    pub confidence: Confidence,
    pub families: &'static [DeviceFamily],
    pub explanation_md: &'static str,
    pub thresholds: Vec<ThresholdSpec>,
}
/// Deterministic, offline rule. Panics are isolated by the runner.
pub trait Rule: Send + Sync {
    fn meta(&self) -> &'static RuleMeta;
    fn evaluate(&self, view: &SnapshotView<'_>, cfg: &RuleConfig) -> Vec<Finding>;
}
