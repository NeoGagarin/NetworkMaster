//! Security rules use presence flags and entered-profile metadata only.
use super::{finding, public_address, router};
use crate::{RuleMeta, SnapshotView};
use nm_core::{DeviceFamily, Finding, HostOrIp, InterfaceRole};
use serde_json::json;
use std::{collections::BTreeMap, sync::LazyLock};
#[derive(serde::Deserialize)]
struct Firmware {
    current: String,
    eol_below: Option<String>,
}
static FIRMWARE: LazyLock<BTreeMap<String, BTreeMap<String, Firmware>>> =
    LazyLock::new(|| toml::from_str(include_str!("../../data/firmware.toml")).unwrap());
fn version(s: &str) -> Vec<u32> {
    s.split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .take(4)
        .filter_map(|s| s.parse().ok())
        .collect()
}
pub(crate) fn evaluate(m: &RuleMeta, v: &SnapshotView<'_>) -> Vec<Finding> {
    let mut out = vec![];
    for (d, r) in v.devices().filter(|(d, _)| m.families.contains(&d.family)) {
        let f = &r.facts;
        let s = &f.services;
        let observed = match m.id.as_str() {
            "UBNT-SEC-001" => v
                .profiles_in_use()
                .find(|p| d.credential_profile == Some(p.id) && p.is_vendor_default)
                .map(|p| {
                    (
                        "credential_profile.is_vendor_default",
                        json!({"profile":p.id,"is_vendor_default":true}),
                    )
                }),
            "UBNT-SEC-002" => match d.management.host {
                HostOrIp::Ip(ip) if public_address(ip) => Some(("management.address", json!(ip))),
                _ => None,
            },
            "UBNT-SEC-003" => (s.https.enabled == Some(false)
                || (s.http.enabled == Some(true) && s.https.enabled == Some(false)))
            .then(|| {
                (
                    "services.http/https",
                    json!({"http":s.http.enabled,"https":s.https.enabled}),
                )
            }),
            "UBNT-SEC-004" => {
                (s.telnet.enabled == Some(true)).then_some(("services.telnet.enabled", json!(true)))
            }
            "UBNT-SEC-005" => (s.snmp.enabled == Some(true)
                && s.snmp.community_is_default == Some(true))
            .then_some(("services.snmp.community_is_default", json!(true))),
            "UBNT-SEC-006" => (router(d, f) && s.upnp.enabled == Some(true))
                .then_some(("services.upnp.enabled", json!(true))),
            "UBNT-SEC-007" => (router(d, f)
                && s.discovery.enabled == Some(true)
                && f.interfaces
                    .iter()
                    .any(|i| v.interface_role(d, i) == Some(InterfaceRole::Wan)))
            .then_some(("services.discovery.enabled", json!(true))),
            "UBNT-SEC-008" => (f.system.ssh_legacy_algorithms == Some(true))
                .then_some(("system.ssh_legacy_algorithms", json!(true))),
            "UBNT-SEC-009" => (f.system.ssh_host_key_changed == Some(true))
                .then_some(("system.ssh_host_key_changed", json!(true))),
            "UBNT-SEC-010" => {
                let family = if d.family == DeviceFamily::AirOs {
                    "airos"
                } else {
                    "edgeos"
                };
                let platform = f
                    .system
                    .platform
                    .as_deref()
                    .or(f.system.model.as_deref())
                    .map(|name| {
                        if name == "EdgeRouter X 5-Port" {
                            "ER-X"
                        } else {
                            name
                        }
                    });
                if let (Some(fw), Some(base)) = (
                    &f.system.firmware,
                    platform.and_then(|p| FIRMWARE.get(family)?.get(p)),
                ) {
                    let old = version(fw) < version(&base.current)
                        || base
                            .eol_below
                            .as_ref()
                            .is_some_and(|e| version(fw) < version(e));
                    old.then(|| {
                        (
                            "system.firmware",
                            json!({"observed":fw,"baseline":base.current,"platform":platform}),
                        )
                    })
                } else {
                    None
                }
            }
            "UBNT-SEC-011" => {
                // Absence is meaningful only with a successfully parsed complete configuration.
                if f.config.is_some() {
                    for i in &f.interfaces {
                        if v.interface_role(d, i) == Some(InterfaceRole::Wan)
                            && i.firewall_in.is_none()
                            && i.firewall_local.is_none()
                        {
                            out.push(finding(m,d.id,format!("interfaces.{}.firewall",i.name.as_deref().unwrap_or("unknown")),json!({"in":i.firewall_in,"local":i.firewall_local,"role":v.interface_role(d,i)}),None));
                        }
                    }
                }
                None
            }
            _ => None,
        };
        if let Some((path, value)) = observed {
            out.push(finding(m, d.id, path, value, None));
        }
    }
    out
}
