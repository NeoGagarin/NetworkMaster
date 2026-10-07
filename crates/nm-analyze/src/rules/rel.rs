//! Link negotiation, routing adjacencies and recent restarts.
use super::finding;
use crate::{RuleConfig, RuleMeta, SnapshotView};
use nm_core::{BgpState, Duplex, Finding, OspfState};
use serde_json::json;
pub(crate) fn gigabit(model: &str) -> bool {
    matches!(
        model,
        "ER-X"
            | "ER-X-SFP"
            | "ER-4"
            | "ER-6P"
            | "ER-8"
            | "ER-12"
            | "ER-Lite"
            | "ER-PoE"
            | "EdgeRouter X 5-Port"
            | "NBE-5AC-Gen2"
            | "PBE-5AC-Gen2"
            | "Rocket 5AC Lite"
            | "R5AC-Lite"
    )
}
// Large byte/uptime counts are compared approximately with configurable fractional thresholds.
#[allow(clippy::cast_precision_loss)]
pub(crate) fn evaluate(m: &RuleMeta, v: &SnapshotView<'_>, cfg: &RuleConfig) -> Vec<Finding> {
    let mut out = vec![];
    for (d, r) in v.devices().filter(|(d, _)| m.families.contains(&d.family)) {
        let f = &r.facts;
        match m.id.as_str() {
            "GEN-REL-002" => {
                for i in &f.interfaces {
                    let peer = f
                        .neighbors
                        .iter()
                        .filter(|n| n.interface == i.name)
                        .filter_map(|n| n.mac.as_ref())
                        .filter_map(|mac| v.mac_index.get(&crate::view::normalize_mac(mac)))
                        .filter_map(|id| v.device(*id))
                        .filter_map(|(_, r)| r.facts.system.model.as_deref())
                        .any(gigabit);
                    if i.duplex == Some(Duplex::Half)
                        || (peer && i.speed_mbps.is_some_and(|n| n > 0 && n < 1000))
                    {
                        out.push(finding(m,d.id,format!("interfaces.{}.negotiation",i.name.as_deref().unwrap_or("unknown")),json!({"speed_mbps":i.speed_mbps,"duplex":i.duplex,"gigabit_peer":peer}),None));
                    }
                }
            }
            "GEN-REL-003" => {
                if let Some(r) = &f.routing {
                    for n in &r.ospf_neighbors {
                        if n.state.is_some_and(|s| s != OspfState::Full) {
                            out.push(finding(
                                m,
                                d.id,
                                "routing.ospf_neighbors",
                                json!(n),
                                Some(json!("Full")),
                            ));
                        }
                    }
                }
            }
            "GEN-REL-004" => {
                if let Some(r) = &f.routing {
                    for n in &r.bgp_peers {
                        if n.state.is_some_and(|s| s != BgpState::Established) {
                            out.push(finding(
                                m,
                                d.id,
                                "routing.bgp_peers",
                                json!(n),
                                Some(json!("Established")),
                            ));
                        }
                    }
                }
            }
            "GEN-REL-005" => {
                if let Some(uptime) = f.system.uptime_seconds {
                    let t = cfg.get_f64(&m.id, "uptime_seconds");
                    if (uptime as f64) < t {
                        out.push(finding(
                            m,
                            d.id,
                            "system.uptime_seconds",
                            json!(uptime),
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
