//! Inventory consistency and collection coverage.
use super::finding;
use crate::{RuleMeta, SnapshotView};
use nm_core::{EnrollmentSource, Finding, Outcome};
use serde_json::json;
pub(crate) fn evaluate(m: &RuleMeta, v: &SnapshotView<'_>) -> Vec<Finding> {
    let mut out = vec![];
    for (d, r) in v.devices().filter(|(d, _)| m.families.contains(&d.family)) {
        let f = &r.facts;
        let observed=match m.id.as_str(){
        "GEN-HYG-001"=>if let(Some(site),Some(model),Some(version))=(d.site,&f.system.model,&f.system.firmware){let mut versions:Vec<_>=v.by_site(site).filter(|(_,r)|r.facts.system.model.as_ref()==Some(model)).filter_map(|(_,r)|r.facts.system.firmware.as_ref()).collect();versions.sort();versions.dedup();(versions.len()>1).then(||("system.firmware",json!({"model":model,"observed":version,"site_versions":versions})))}else{None},
        "GEN-HYG-002"=>f.system.hostname.as_ref().filter(|s|matches!(s.to_ascii_lowercase().as_str(),"ubnt"|"ubiquiti"|"edgeos"|"edgerouter"|"nanostation"|"rocket"|"airgrid"|"litebeam"|"powerbeam")).map(|s|("system.hostname",json!(s))),
        "GEN-HYG-003"=>(f.config.is_some()&&f.system.ntp_servers.is_empty()).then(||("system.ntp_servers",json!([]))),
        "GEN-HYG-004"=>(d.site.is_some()&&d.source==EnrollmentSource::Manual&&v.devices().any(|(other,_)|other.id!=d.id&&other.site==d.site&&other.family==d.family&&matches!(other.source,EnrollmentSource::UispImport|EnrollmentSource::UniFiImport))).then(||("inventory.source",json!(d.source))),
        "GEN-HYG-005"=>(!matches!(r.outcome,Outcome::Ok)||!r.coverage.missing.is_empty()).then(||("coverage.missing",json!({"outcome":r.outcome,"missing":r.coverage.missing,"errors":r.coverage.errors}))),_=>None
    };
        if let Some((path, value)) = observed {
            out.push(finding(m, d.id, path, value, None));
        }
    }
    out
}
