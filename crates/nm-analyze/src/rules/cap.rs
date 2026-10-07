//! Capacity rules require observed totals; missing counts never become zeroes.
use super::finding;
use crate::{RuleConfig, RuleMeta, SnapshotView};
use nm_core::{Finding, RadioMode};
use serde_json::json;
pub(crate) fn evaluate(m: &RuleMeta, v: &SnapshotView<'_>, cfg: &RuleConfig) -> Vec<Finding> {
    let mut out = vec![];
    for (d, r) in v.devices().filter(|(d, _)| m.families.contains(&d.family)) {
        match m.id.as_str() {
            "GEN-CAP-001" => {
                if let Some(dhcp) = &r.facts.dhcp {
                    for p in &dhcp.pools {
                        let t = cfg.get_f64(&m.id, "pool_ratio");
                        if let (Some(size), Some(leased)) = (p.size, p.leased) {
                            if size > 0 && f64::from(leased) / f64::from(size) > t {
                                out.push(finding(m, d.id, "dhcp.pools", json!(p), Some(json!(t))));
                            }
                        }
                    }
                }
            }
            "GEN-CAP-002" => {
                if let Some(radio) = &r.facts.radio {
                    let t = cfg.get_f64(&m.id, "max_stations");
                    if radio.mode == Some(RadioMode::Ap)
                        && u32::try_from(radio.stations.len()).map_or(f64::INFINITY, f64::from) > t
                    {
                        out.push(finding(
                            m,
                            d.id,
                            "radio.stations.count",
                            json!({"stations":radio.stations.len(),"model":r.facts.system.model}),
                            Some(json!(t)),
                        ));
                    }
                }
            }
            _ => {}
        }
    }
    out
}
