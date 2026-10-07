//! RF rules include AP-only station observations and explicitly marked heuristics.
use super::finding;
use crate::{RuleConfig, RuleMeta, SnapshotView};
use nm_core::{ChainSignal, Evidence, Finding, RadioMode};
use serde_json::json;
use std::sync::LazyLock;
#[derive(serde::Deserialize)]
struct McsTable {
    bands: Vec<McsBand>,
}
#[derive(serde::Deserialize)]
struct McsBand {
    width: u16,
    signal_dbm: i16,
    minimum: u8,
}
static MCS: LazyLock<McsTable> =
    LazyLock::new(|| toml::from_str(include_str!("../../data/mcs_expect.toml")).unwrap());
fn expected(width: u16, signal: i16) -> Option<u8> {
    MCS.bands
        .iter()
        .filter(|b| b.width == width && signal >= b.signal_dbm)
        .map(|b| b.minimum)
        .max()
}
fn imbalance(chains: &[ChainSignal]) -> Option<i32> {
    let v: Vec<_> = chains.iter().filter_map(|c| c.rssi_dbm).collect();
    if v.len() < 2 {
        return None;
    }
    Some(i32::from(*v.iter().max()?) - i32::from(*v.iter().min()?))
}
pub(crate) fn evaluate(m: &RuleMeta, v: &SnapshotView<'_>, cfg: &RuleConfig) -> Vec<Finding> {
    let mut out = vec![];
    if m.id.as_str() == "UBNT-RF-006" {
        let radios: Vec<_> = v
            .radios()
            .filter(|(d, r)| d.site.is_some() && r.mode == Some(RadioMode::Ap))
            .collect();
        for (i, (a, ra)) in radios.iter().enumerate() {
            for (b, rb) in &radios[i + 1..] {
                if a.site != b.site {
                    continue;
                }
                if let (Some(fa), Some(fb), Some(wa), Some(wb)) = (
                    ra.frequency_mhz,
                    rb.frequency_mhz,
                    ra.channel_width_mhz,
                    rb.channel_width_mhz,
                ) {
                    if f64::from(fa.abs_diff(fb)) < f64::midpoint(f64::from(wa), f64::from(wb)) {
                        let mut f = finding(
                            m,
                            a.id,
                            "radio.channel",
                            json!({"frequency_mhz":fa,"width_mhz":wa}),
                            None,
                        );
                        f.devices.push(b.id);
                        f.evidence.push(Evidence {
                            device_id: b.id,
                            metric_path: "radio.channel".into(),
                            observed: json!({"frequency_mhz":fb,"width_mhz":wb}),
                            threshold: None,
                        });
                        out.push(f);
                    }
                }
            }
        }
        return out;
    }
    for (d, r) in v.radios().filter(|(d, _)| m.families.contains(&d.family)) {
        // Radio and station observations share identical thresholds and evidence format.
        let mut samples = vec![(
            "radio".to_owned(),
            &r.chains,
            r.ccq_pct,
            r.signal_dbm,
            r.mcs,
            r.distance_m,
        )];
        if r.mode == Some(RadioMode::Ap) {
            samples.extend(r.stations.iter().enumerate().map(|(i, s)| {
                (
                    format!(
                        "radio.stations.{}",
                        s.mac.as_ref().map_or_else(|| i.to_string(), Clone::clone)
                    ),
                    &s.chains,
                    s.ccq_pct,
                    s.signal_dbm,
                    s.mcs,
                    s.distance_m,
                )
            }));
        }
        for (path, chains, ccq, signal, mcs, distance) in samples {
            match m.id.as_str() {
                "UBNT-RF-001" => {
                    let t = cfg.get_f64(&m.id, "imbalance_db");
                    if imbalance(chains).is_some_and(|n| f64::from(n) > t) {
                        out.push(finding(
                            m,
                            d.id,
                            format!("{path}.chains"),
                            json!(chains),
                            Some(json!(t)),
                        ));
                    }
                }
                "UBNT-RF-002" => {
                    let t = cfg.get_f64(&m.id, "ccq_pct");
                    if ccq.is_some_and(|n| f64::from(n) < t) {
                        out.push(finding(
                            m,
                            d.id,
                            format!("{path}.ccq_pct"),
                            json!(ccq),
                            Some(json!(t)),
                        ));
                    }
                }
                "UBNT-RF-004" => {
                    let t = cfg.get_f64(&m.id, "signal_dbm");
                    if (path != "radio"
                        || matches!(r.mode, Some(RadioMode::Station | RadioMode::PtpSlave)))
                        && signal.is_some_and(|n| f64::from(n) < t)
                    {
                        out.push(finding(
                            m,
                            d.id,
                            format!("{path}.signal_dbm"),
                            json!(signal),
                            Some(json!(t)),
                        ));
                    }
                }
                "UBNT-RF-007" => {
                    if let (Some(signal), Some(mcs), Some(width)) =
                        (signal, mcs, r.channel_width_mhz)
                    {
                        if let Some(e) = expected(width, signal) {
                            if mcs.saturating_add(2) < e {
                                out.push(finding(
                                    m,
                                    d.id,
                                    format!("{path}.mcs"),
                                    json!({"mcs":mcs,"signal_dbm":signal,"width_mhz":width}),
                                    Some(json!(e)),
                                ));
                            }
                        }
                    }
                }
                "UBNT-RF-009" => {
                    if let Some(limit) = v
                        .sites()
                        .find(|s| Some(s.id) == d.site)
                        .and_then(|s| s.max_distance_m)
                    {
                        if (path != "radio"
                            || matches!(r.mode, Some(RadioMode::Station | RadioMode::PtpSlave)))
                            && distance.is_some_and(|n| n > limit)
                        {
                            out.push(finding(
                                m,
                                d.id,
                                format!("{path}.distance_m"),
                                json!(distance),
                                Some(json!(limit)),
                            ));
                        }
                    }
                }
                _ => {}
            }
        }
        match m.id.as_str() {
            "UBNT-RF-003" => {
                let t = cfg.get_f64(&m.id, "airtime_pct");
                if r.airtime_pct
                    .as_ref()
                    .and_then(|a| a.busy)
                    .is_some_and(|n| f64::from(n) > t)
                {
                    out.push(finding(
                        m,
                        d.id,
                        "radio.airtime_pct.busy",
                        json!(r.airtime_pct),
                        Some(json!(t)),
                    ));
                }
            }
            "UBNT-RF-005" => {
                let t = cfg.get_f64(&m.id, "noise_dbm");
                if r.mode == Some(RadioMode::Ap)
                    && r.noise_floor_dbm.is_some_and(|n| f64::from(n) > t)
                {
                    out.push(finding(
                        m,
                        d.id,
                        "radio.noise_floor_dbm",
                        json!(r.noise_floor_dbm),
                        Some(json!(t)),
                    ));
                }
            }
            "UBNT-RF-008" => {
                let width = cfg.get_f64(&m.id, "wide_mhz");
                let throughput = cfg.get_f64(&m.id, "throughput_mbps");
                if r.channel_width_mhz.is_some_and(|w| f64::from(w) > width)
                    && r.throughput_mbps.is_some_and(|t| t < throughput)
                {
                    out.push(finding(m,d.id,"radio.width/throughput",json!({"width_mhz":r.channel_width_mhz,"throughput_mbps":r.throughput_mbps}),Some(json!({"width_mhz":width,"throughput_mbps":throughput}))));
                }
            }
            _ => {}
        }
    }
    out
}
