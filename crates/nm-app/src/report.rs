//! Markdown report rendering shared by CLI and TUI, without model calls.
use nm_core::{
    redact::{RedactionLevel, Redactor},
    Device, DeviceId, DeviceResult, Finding, HostOrIp, Severity, Site, Snapshot,
};
use std::{collections::BTreeMap, fmt::Write};
/// Report filters and identity redaction, defaulting to full redaction.
#[derive(Clone, Debug, Default)]
pub struct ReportOptions {
    pub redact: RedactionLevel,
    pub min_severity: Option<Severity>,
    pub devices: Vec<Device>,
    pub sites: Vec<Site>,
}
/// Escape untrusted observation text for Markdown table cells.
fn cell(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('|', "&#124;")
        .replace(['\n', '\r'], " ")
        .replace('`', "&#96;")
}
/// Render only observed facts and deterministic findings, with coverage gaps visible.
pub fn render_report(snapshot: &Snapshot, findings: &[Finding], options: &ReportOptions) -> String {
    let mut out = String::new();
    let mut redactor = Redactor::default();
    for d in &options.devices {
        redactor.register(&d.display_name, "device");
        if let HostOrIp::Hostname(s) = &d.management.host {
            redactor.register(s, "host");
        }
    }
    for site in &options.sites {
        redactor.register(&site.name, "site");
    }
    for r in &snapshot.device_results {
        let f = &r.facts;
        if let Some(s) = &f.system.hostname {
            redactor.register(s, "host");
        }
        if let Some(s) = &f.system.serial {
            redactor.register(s, "serial");
        }
        if let Some(s) = f.radio.as_ref().and_then(|r| r.ssid.as_ref()) {
            redactor.register(s, "ssid");
        }
        for n in &f.neighbors {
            if let Some(s) = &n.hostname {
                redactor.register(s, "host");
            }
        }
        if let Some(r) = &f.radio {
            for s in &r.stations {
                if let Some(h) = &s.hostname {
                    redactor.register(h, "host");
                }
                if let Some(h) = s.remote.as_ref().and_then(|s| s.hostname.as_ref()) {
                    redactor.register(h, "host");
                }
            }
        }
    }
    if options.redact == RedactionLevel::Full {
        redactor.register(&snapshot.id.to_string(), "snapshot");
        for d in &options.devices {
            redactor.register(&d.id.to_string(), "device-id");
            if let Some(p) = d.credential_profile {
                redactor.register(&p.to_string(), "profile");
            }
        }
        for r in &snapshot.device_results {
            redactor.register(&r.device_id.to_string(), "device-id");
        }
    }
    let name = |id: DeviceId| {
        options
            .devices
            .iter()
            .find(|d| d.id == id)
            .map_or_else(|| id.to_string(), |d| d.display_name.clone())
    };
    writeln!(out,"# NetworkMaster assessment\n\nSnapshot: `{}`  \nStarted: {}  \nFinished: {}  \nDevices: {}\n",snapshot.id,snapshot.started_at,snapshot.finished_at.map_or_else(||"in progress".into(),|t|t.to_string()),snapshot.device_results.len()).unwrap();
    let mut families = BTreeMap::new();
    let mut sites = BTreeMap::<String, Vec<&DeviceResult>>::new();
    for r in &snapshot.device_results {
        let d = options.devices.iter().find(|d| d.id == r.device_id);
        *families
            .entry(d.map_or_else(|| "Unknown".into(), |d| format!("{:?}", d.family)))
            .or_insert(0usize) += 1;
        let site = d
            .and_then(|d| d.site)
            .and_then(|id| options.sites.iter().find(|s| s.id == id))
            .map_or_else(|| "Unassigned".into(), |s| s.name.clone());
        sites.entry(site).or_default().push(r);
    }
    out.push_str("## Snapshot coverage\n\n| Family | Devices |\n| --- | --- |\n");
    for (family, n) in families {
        writeln!(out, "| {family} | {n} |").unwrap();
    }
    let collected: usize = snapshot
        .device_results
        .iter()
        .map(|r| r.coverage.collected.len())
        .sum();
    let missing: usize = snapshot
        .device_results
        .iter()
        .map(|r| r.coverage.missing.len())
        .sum();
    let skipped: usize = snapshot
        .device_results
        .iter()
        .map(|r| r.coverage.skipped.len())
        .sum();
    writeln!(out,"\nArtifacts: {collected} collected, {missing} missing, {skipped} skipped by configuration.\n").unwrap();
    let mut findings: Vec<_> = findings
        .iter()
        .filter(|f| options.min_severity.is_none_or(|s| f.severity >= s))
        .collect();
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.rule_id.as_str().cmp(b.rule_id.as_str()))
            .then_with(|| a.id.cmp(&b.id))
    });
    if findings.is_empty() {
        out.push_str("## Findings\n\nNo findings match the selected filters. Incomplete coverage can hide conditions.\n\n");
    }
    let mut severity = None;
    for f in findings {
        if severity != Some(f.severity) {
            writeln!(out, "## {:?} findings\n", f.severity).unwrap();
            severity = Some(f.severity);
        }
        writeln!(out,"### {} — {}\n\nCategory: {:?} · Confidence: {:?}\n\nAffected devices: {}\n\n{}\n\n| Device | Metric | Observed | Threshold |\n| --- | --- | --- | --- |",f.rule_id,cell(&f.title),f.category,f.confidence,f.devices.iter().map(|id|cell(&name(*id))).collect::<Vec<_>>().join(", "),f.explanation).unwrap();
        for e in &f.evidence {
            writeln!(
                out,
                "| {} | {} | {} | {} |",
                cell(&name(e.device_id)),
                cell(&e.metric_path),
                cell(&e.observed.to_string()),
                cell(
                    &e.threshold
                        .as_ref()
                        .map_or_else(|| "—".into(), ToString::to_string)
                )
            )
            .unwrap();
        }
        out.push('\n');
    }
    out.push_str("## Device summary by site\n\n");
    for (site, devices) in sites {
        writeln!(
            out,
            "### {}\n\n| Device | Model | Firmware | Outcome |\n| --- | --- | --- | --- |",
            cell(&site)
        )
        .unwrap();
        for r in devices {
            writeln!(
                out,
                "| {} | {} | {} | {} |",
                cell(&name(r.device_id)),
                cell(r.facts.system.model.as_deref().unwrap_or("Unknown")),
                cell(r.facts.system.firmware.as_deref().unwrap_or("Unknown")),
                cell(&format!("{:?}", r.outcome))
            )
            .unwrap();
        }
        out.push('\n');
    }
    out.push_str("## Appendix: coverage gaps\n\n");
    for r in &snapshot.device_results {
        if r.coverage.missing.is_empty()
            && r.coverage.errors.is_empty()
            && r.coverage.skipped.is_empty()
        {
            continue;
        }
        writeln!(out, "### {}\n", cell(&name(r.device_id))).unwrap();
        for artifact in &r.coverage.missing {
            writeln!(out, "- Missing: {}", cell(artifact)).unwrap();
        }
        for (a, e) in &r.coverage.errors {
            writeln!(out, "- {}: {}", cell(a), cell(e)).unwrap();
        }
        for (a, e) in &r.coverage.skipped {
            writeln!(out, "- {}: {}", cell(a), cell(e)).unwrap();
        }
        out.push('\n');
    }
    redactor.redact(&out, options.redact)
}
