//! Panic isolation, deterministic finding IDs and stable severity ordering.
use crate::{Rule, RuleConfig, SnapshotView};
use nm_core::{Category, Confidence, Finding, FindingId, RuleId, Severity};
use sha2::{Digest, Sha256};
use std::panic::{catch_unwind, AssertUnwindSafe};
/// Evaluate enabled catalog rules applicable to families in the snapshot.
pub fn evaluate(view: &SnapshotView<'_>, cfg: &RuleConfig) -> Vec<Finding> {
    evaluate_rules(view, cfg, crate::catalog::all())
}
/// Evaluate a supplied registry, also used to test panic isolation.
pub fn evaluate_rules(
    view: &SnapshotView<'_>,
    cfg: &RuleConfig,
    rules: &[&dyn Rule],
) -> Vec<Finding> {
    let mut findings = vec![];
    for rule in rules {
        let m = rule.meta();
        if !cfg.is_enabled(&m.id)
            || !view
                .devices()
                .any(|(d, _)| m.families.is_empty() || m.families.contains(&d.family))
        {
            continue;
        }
        match catch_unwind(AssertUnwindSafe(||rule.evaluate(view,cfg))){
            Ok(f)=>findings.extend(f),Err(_)=>findings.push(Finding{id:FindingId::new(),rule_id:RuleId::new("GEN-HYG-999").unwrap(),severity:Severity::Info,category:Category::Hygiene,devices:vec![],title:format!("Rule crashed: {}",m.id),evidence:vec![],explanation:format!("Rule {} failed while evaluating this snapshot. Other rules continued. Report this rule ID to the maintainer.",m.id),confidence:Confidence::Certain})
        }
    }
    for f in &mut findings {
        f.devices.sort();
        let bytes = serde_json::to_vec(&(
            view.snapshot.id,
            &f.rule_id,
            &f.devices,
            &f.evidence,
            &f.title,
        ))
        .unwrap();
        let hash = Sha256::digest(bytes);
        let mut id = [0u8; 16];
        id.copy_from_slice(&hash[..16]);
        f.id = ulid::Ulid::from_bytes(id).to_string().parse().unwrap();
    }
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.rule_id.as_str().cmp(b.rule_id.as_str()))
            .then_with(|| a.devices.cmp(&b.devices))
            .then_with(|| a.id.cmp(&b.id))
    });
    findings
}
