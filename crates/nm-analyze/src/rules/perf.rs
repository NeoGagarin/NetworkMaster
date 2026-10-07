//! Resource pressure and supported hardware offload checks.
use super::finding;
use crate::{RuleConfig, RuleMeta, SnapshotView};
use nm_core::{Capabilities, Finding};
use serde_json::json;
/// Model CPU fallback, used only when a model is positively identified.
pub fn cpu_count(model: &str) -> Option<u32> {
    match model {
        "ER-X" | "ER-X-SFP" | "EdgeRouter X 5-Port" | "ER-4" | "ER-6P" | "ER-12" => Some(4),
        "ER-8" | "ER-Lite" | "ER-PoE" => Some(2),
        _ => None,
    }
}
// Large byte/uptime counts are compared approximately with configurable fractional thresholds.
#[allow(clippy::cast_precision_loss)]
pub(crate) fn evaluate(m: &RuleMeta, v: &SnapshotView<'_>, cfg: &RuleConfig) -> Vec<Finding> {
    let mut out = vec![];
    for (d, r) in v.devices().filter(|(d, _)| m.families.contains(&d.family)) {
        let s = &r.facts.system;
        match m.id.as_str() {
            "UBNT-PERF-001" => {
                let model = s.model.as_deref().map(|s| {
                    if s == "EdgeRouter X 5-Port" {
                        "ER-X"
                    } else {
                        s
                    }
                });
                if model.is_some_and(|name| {
                    Capabilities::for_family(d.family)
                        .is_some_and(|c| c.offload_models.iter().any(|m| m == name))
                }) && s
                    .offload
                    .as_ref()
                    .is_some_and(|o| o.ipv4_forwarding == Some(false))
                {
                    out.push(finding(
                        m,
                        d.id,
                        "system.offload.ipv4_forwarding",
                        json!({"model":model,"enabled":false}),
                        None,
                    ));
                }
            }
            "UBNT-PERF-002" => {
                if let (Some(load), Some(cores)) = (
                    s.loadavg.as_ref().and_then(|l| l.one_min),
                    s.cpu_count.or_else(|| cpu_count(s.model.as_deref()?)),
                ) {
                    let threshold = f64::from(cores) * cfg.get_f64(&m.id, "load_factor");
                    if load > threshold {
                        out.push(finding(
                            m,
                            d.id,
                            "system.loadavg.one_min",
                            json!({"load":load,"cpu_count":cores}),
                            Some(json!(threshold)),
                        ));
                    }
                }
            }
            "UBNT-PERF-003" => {
                if let Some(mem) = &s.memory {
                    if let (Some(total), Some(free)) =
                        (mem.total_bytes, mem.available_bytes.or(mem.free_bytes))
                    {
                        let threshold = cfg.get_f64(&m.id, "memory_pct");
                        if total > 0 && free as f64 / (total as f64) * 100.0 < threshold {
                            out.push(finding(
                                m,
                                d.id,
                                "system.memory",
                                json!({"total_bytes":total,"available_bytes":free}),
                                Some(json!(threshold)),
                            ));
                        }
                    }
                }
            }
            _ => {}
        }
    }
    out
}
