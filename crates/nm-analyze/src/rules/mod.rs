//! Catalog implementations, grouped by the documented assessment categories.
pub mod cap;
pub mod hyg;
pub mod perf;
pub mod rel;
pub mod rf;
pub mod sec;
use crate::{Rule, RuleConfig, RuleMeta, SnapshotView};
use nm_core::{
    finding, Category, Device, DeviceFacts, DeviceFamily, DeviceId, DeviceRole, Evidence, Finding,
    FindingId,
};
use serde_json::Value;
pub(crate) struct CatalogRule(pub usize);
impl Rule for CatalogRule {
    fn meta(&self) -> &'static RuleMeta {
        &crate::catalog::META[self.0]
    }
    fn evaluate(&self, view: &SnapshotView<'_>, cfg: &RuleConfig) -> Vec<Finding> {
        let m = self.meta();
        match m.category {
            Category::Security => sec::evaluate(m, view),
            Category::Hygiene => hyg::evaluate(m, view),
            Category::RfHealth => rf::evaluate(m, view, cfg),
            Category::Performance => perf::evaluate(m, view, cfg),
            Category::Reliability => rel::evaluate(m, view, cfg),
            Category::Capacity => cap::evaluate(m, view, cfg),
        }
    }
}
pub(crate) fn finding(
    m: &RuleMeta,
    d: DeviceId,
    path: impl Into<String>,
    observed: Value,
    threshold: Option<Value>,
) -> Finding {
    Finding {
        id: FindingId::new(),
        rule_id: m.id.clone(),
        severity: m.default_severity,
        category: m.category,
        devices: vec![d],
        title: m.title.into(),
        evidence: vec![Evidence {
            device_id: d,
            metric_path: path.into(),
            observed,
            threshold,
        }],
        explanation: m.explanation_md.into(),
        confidence: m.confidence,
    }
}
pub(crate) fn router(d: &Device, f: &DeviceFacts) -> bool {
    d.family == DeviceFamily::EdgeOs
        || matches!(d.role, Some(DeviceRole::Router | DeviceRole::Gateway))
        || f.system.netrole.as_deref() == Some("router")
}
/// True for addresses outside private, shared, local, unspecified and multicast ranges.
pub fn public_address(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(a) => {
            !a.is_private()
                && !a.is_link_local()
                && !a.is_loopback()
                && !a.is_unspecified()
                && !a.is_multicast()
                && !a.is_broadcast()
                && !(a.octets()[0] == 100 && (64..128).contains(&a.octets()[1]))
        }
        std::net::IpAddr::V6(a) => {
            if let Some(v4) = a.to_ipv4_mapped() {
                public_address(v4.into())
            } else {
                !a.is_unique_local()
                    && !a.is_unicast_link_local()
                    && !a.is_loopback()
                    && !a.is_unspecified()
                    && !a.is_multicast()
            }
        }
    }
}
