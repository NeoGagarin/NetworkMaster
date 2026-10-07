use nm_analyze::{Rule, RuleConfig, SnapshotView};
use nm_core::*;
use serde_json::json;
use std::result::Result;

fn device(n: u8) -> Device {
    Device {
        id: format!("0000000000000000000000000{n}").parse().unwrap(),
        display_name: format!("device-{n}"),
        management: format!("10.0.0.{n}").parse().unwrap(),
        vendor: Vendor::Ubiquiti,
        family: DeviceFamily::AirOs,
        role: None,
        site: Some("00000000000000000000000001".parse().unwrap()),
        credential_profile: None,
        source: EnrollmentSource::Manual,
        enrolled: true,
        ssh_legacy_ok: false,
        tags: vec![],
        interface_roles: std::collections::BTreeMap::default(),
    }
}
fn fixture(id: &str, bad: bool) -> (Snapshot, Vec<Device>, Vec<Site>, Vec<CredentialProfile>) {
    let mut devices = vec![device(1), device(2)];
    let mut profiles = vec![];
    let mut facts = DeviceFacts::default();
    let mut other = DeviceFacts::default();
    let mut coverage = Coverage::default();
    let mut outcome = Outcome::Ok;
    let site = Site {
        id: devices[0].site.unwrap(),
        name: "Test site".into(),
        notes: String::new(),
        max_distance_m: Some(1000),
    };
    let value = match id {
        "UBNT-SEC-001" => {
            let p = CredentialProfile {
                id: CredentialProfileId::new(),
                name: "operator profile".into(),
                kind: CredentialKind::SshPassword {
                    username: "ubnt".into(),
                },
                storage: StorageMode::SessionOnly,
                scope_hint: String::new(),
                is_vendor_default: bad,
            };
            devices[0].credential_profile = Some(p.id);
            profiles.push(p);
            json!({})
        }
        "UBNT-SEC-002" => {
            devices[0].management = if bad { "8.8.8.8" } else { "100.64.0.1" }.parse().unwrap();
            json!({})
        }
        "UBNT-SEC-003" => json!({"services":{"http":{"enabled":true},"https":{"enabled":!bad}}}),
        "UBNT-SEC-004" => json!({"services":{"telnet":{"enabled":bad}}}),
        "UBNT-SEC-005" => json!({"services":{"snmp":{"enabled":true,"community_is_default":bad}}}),
        "UBNT-SEC-006" => {
            devices[0].role = Some(DeviceRole::Router);
            json!({"services":{"upnp":{"enabled":bad}}})
        }
        "UBNT-SEC-007" => {
            devices[0].role = Some(DeviceRole::Router);
            json!({"services":{"discovery":{"enabled":bad}},"interfaces":[{"name":"eth0","role":"Wan"}]})
        }
        "UBNT-SEC-008" => json!({"system":{"ssh_legacy_algorithms":bad}}),
        "UBNT-SEC-009" => json!({"system":{"ssh_host_key_changed":bad}}),
        "UBNT-SEC-010" => {
            json!({"system":{"platform":"WA","firmware":if bad{"WA.v8.7.11"}else{"WA.v8.7.25"}}})
        }
        "UBNT-SEC-011" => {
            devices[0].family = DeviceFamily::EdgeOs;
            json!({"config":{"text":"set interfaces ethernet eth0 address dhcp"},"interfaces":[{"name":"eth0","role":"Wan","firewall_in":if bad{None}else{Some("WAN_IN")}}]})
        }
        "UBNT-RF-001" => {
            json!({"radio":{"mode":"Ap","stations":[{"mac":"02:00:00:00:00:03","chains":[{"chain":0,"rssi_dbm":-55},{"chain":1,"rssi_dbm":if bad{-65}else{-61}}]}]}})
        }
        "UBNT-RF-002" => json!({"radio":{"mode":"Station","ccq_pct":if bad{69}else{70}}}),
        "UBNT-RF-003" => {
            json!({"radio":{"mode":"Ap","airtime_pct":{"busy":if bad{81.0}else{80.0}}}})
        }
        "UBNT-RF-004" => json!({"radio":{"mode":"Station","signal_dbm":if bad{-76}else{-75}}}),
        "UBNT-RF-005" => json!({"radio":{"mode":"Ap","noise_floor_dbm":if bad{-89}else{-90}}}),
        "UBNT-RF-006" => {
            other=serde_json::from_value(json!({"radio":{"mode":"Ap","frequency_mhz":if bad{5800}else{5820},"channel_width_mhz":20}})).unwrap();
            json!({"radio":{"mode":"Ap","frequency_mhz":5800,"channel_width_mhz":20}})
        }
        "UBNT-RF-007" => {
            json!({"radio":{"mode":"Station","signal_dbm":-55,"channel_width_mhz":20,"mcs":if bad{4}else{5}}})
        }
        "UBNT-RF-008" => {
            json!({"radio":{"mode":"Ap","channel_width_mhz":80,"throughput_mbps":if bad{9.0}else{10.0}}})
        }
        "UBNT-RF-009" => json!({"radio":{"mode":"Station","distance_m":if bad{1001}else{1000}}}),
        "UBNT-PERF-001" => {
            devices[0].family = DeviceFamily::EdgeOs;
            json!({"system":{"model":"ER-X","offload":{"ipv4_forwarding":!bad}}})
        }
        "UBNT-PERF-002" => {
            json!({"system":{"cpu_count":4,"loadavg":{"one_min":if bad{4.1}else{4.0}}}})
        }
        "UBNT-PERF-003" => {
            json!({"system":{"memory":{"total_bytes":1000,"available_bytes":if bad{99}else{100}}}})
        }
        "GEN-REL-002" => {
            json!({"interfaces":[{"name":"eth0","duplex":if bad{"Half"}else{"Full"},"speed_mbps":1000}]})
        }
        "GEN-REL-003" => {
            json!({"routing":{"ospf_neighbors":[{"router_id":"10.0.0.2","state":if bad{"Init"}else{"Full"}}]}})
        }
        "GEN-REL-004" => {
            json!({"routing":{"bgp_peers":[{"address":"10.0.0.2","state":if bad{"Active"}else{"Established"}}]}})
        }
        "GEN-REL-005" => json!({"system":{"uptime_seconds":if bad{86399}else{86400}}}),
        "GEN-CAP-001" => {
            json!({"dhcp":{"pools":[{"name":"LAN","size":100,"leased":if bad{91}else{90}}]}})
        }
        "GEN-CAP-002" => {
            facts.radio = Some(RadioFacts {
                mode: Some(RadioMode::Ap),
                stations: vec![StationFacts::default(); if bad { 61 } else { 60 }],
                ..Default::default()
            });
            json!({})
        }
        "GEN-HYG-001" => {
            other.system.model = Some("ER-X".into());
            other.system.firmware = Some(if bad { "2.0.8" } else { "2.0.9" }.into());
            json!({"system":{"model":"ER-X","firmware":"2.0.9"}})
        }
        "GEN-HYG-002" => json!({"system":{"hostname":if bad{"ubnt"}else{"North router"}}}),
        "GEN-HYG-003" => {
            json!({"config":{"text":"set system host-name router"},"system":{"ntp_servers":if bad{vec![]}else{vec!["10.0.0.100"]}}})
        }
        "GEN-HYG-004" => {
            devices[1].source = if bad {
                EnrollmentSource::UispImport
            } else {
                EnrollmentSource::Manual
            };
            json!({})
        }
        "GEN-HYG-005" => {
            if bad {
                outcome = Outcome::Partial(vec!["version".into()]);
                coverage.missing.push("version".into());
            }
            json!({})
        }
        _ => panic!("missing test case {id}"),
    };
    let parsed: DeviceFacts = serde_json::from_value(value).unwrap();
    if id != "GEN-CAP-002" {
        facts = parsed;
    }
    let snapshot = Snapshot {
        id: "00000000000000000000000003".parse().unwrap(),
        started_at: Timestamp::now(),
        finished_at: Some(Timestamp::now()),
        device_results: vec![
            DeviceResult {
                device_id: devices[0].id,
                outcome,
                facts,
                raw: vec![],
                coverage,
            },
            DeviceResult {
                device_id: devices[1].id,
                outcome: Outcome::Ok,
                facts: other,
                raw: vec![],
                coverage: Coverage::default(),
            },
        ],
        findings: vec![],
    };
    (snapshot, devices, vec![site], profiles)
}
#[test]
fn every_catalog_rule_has_positive_negative_and_unavailable_cases() {
    assert_eq!(nm_analyze::catalog::all().len(), 34);
    for rule in nm_analyze::catalog::all() {
        for bad in [true, false] {
            let (s, d, sites, p) = fixture(rule.meta().id.as_str(), bad);
            let view = SnapshotView::new(&s, &d, &sites, &p);
            let f = rule.evaluate(&view, &RuleConfig::default());
            assert_eq!(!f.is_empty(), bad, "{} bad={bad}: {f:?}", rule.meta().id);
            for f in f {
                assert!(!f.evidence.is_empty());
                assert_eq!(f.confidence, rule.meta().confidence);
            }
        }
        let (s, mut d, sites, p) = fixture("UBNT-SEC-002", false);
        d[0].family = rule.meta().families[0];
        assert!(
            rule.evaluate(
                &SnapshotView::new(&s, &d, &sites, &p),
                &RuleConfig::default()
            )
            .is_empty(),
            "unknown facts: {}",
            rule.meta().id
        );
    }
}
#[test]
#[allow(clippy::many_single_char_names)]
fn deterministic_runner_threshold_disable_and_documentation() {
    let (s, d, sites, p) = fixture("UBNT-RF-001", true);
    let v = SnapshotView::new(&s, &d, &sites, &p);
    let mut cfg = RuleConfig::default();
    let a = nm_analyze::runner::evaluate(&v, &cfg);
    assert_eq!(a, nm_analyze::runner::evaluate(&v, &cfg));
    let id = RuleId::new("UBNT-RF-001").unwrap();
    cfg.thresholds
        .entry(id.clone())
        .or_default()
        .insert("imbalance_db".into(), toml::Value::Integer(10));
    assert!(!nm_analyze::runner::evaluate(&v, &cfg)
        .iter()
        .any(|f| f.rule_id == id));
    cfg.enabled.insert(id.clone(), false);
    assert!(!nm_analyze::runner::evaluate(&v, &cfg)
        .iter()
        .any(|f| f.rule_id == id));
    let bundled: RuleConfig = toml::from_str(include_str!("../data/defaults.toml")).unwrap();
    bundled.validate().unwrap();
    for rule in nm_analyze::catalog::all() {
        for threshold in &rule.meta().thresholds {
            assert_eq!(
                bundled.get_f64(&rule.meta().id, threshold.key).to_bits(),
                RuleConfig::default()
                    .get_f64(&rule.meta().id, threshold.key)
                    .to_bits()
            );
        }
    }
    assert_eq!(
        nm_analyze::catalog::export_md(),
        nm_analyze::catalog::export_md()
    );
}
struct PanicRule;
impl Rule for PanicRule {
    fn meta(&self) -> &'static nm_analyze::RuleMeta {
        nm_analyze::catalog::all()[0].meta()
    }
    fn evaluate(&self, _: &SnapshotView<'_>, _: &RuleConfig) -> Vec<Finding> {
        panic!("planted panic");
    }
}
#[test]
fn a_panicking_rule_does_not_hide_other_findings() {
    let (s, d, sites, p) = fixture("UBNT-RF-001", true);
    let good = nm_analyze::catalog::all()
        .iter()
        .find(|r| r.meta().id.as_str() == "UBNT-RF-001")
        .unwrap();
    let f = nm_analyze::runner::evaluate_rules(
        &SnapshotView::new(&s, &d, &sites, &p),
        &RuleConfig::default(),
        &[&PanicRule, *good],
    );
    assert!(f.iter().any(|f| f.rule_id.as_str() == "GEN-HYG-999"));
    assert!(f.iter().any(|f| f.rule_id.as_str() == "UBNT-RF-001"));
}
#[test]
fn role_overrides_and_public_ip_exclusions() {
    for address in [
        "10.1.1.1",
        "100.64.0.1",
        "100.127.255.254",
        "169.254.1.1",
        "127.0.0.1",
        "::1",
        "fd00::1",
        "fe80::1",
        "::ffff:10.1.1.1",
        "0.0.0.0",
    ] {
        assert!(
            !nm_analyze::rules::public_address(address.parse().unwrap()),
            "{address}"
        );
    }
    for address in ["8.8.8.8", "100.128.0.1", "2001:4860:4860::8888"] {
        assert!(nm_analyze::rules::public_address(address.parse().unwrap()));
    }
    let (s, mut d, sites, p) = fixture("UBNT-SEC-011", true);
    d[0].interface_roles
        .insert("eth0".into(), InterfaceRole::Lan);
    let rule = nm_analyze::catalog::all()
        .iter()
        .find(|r| r.meta().id.as_str() == "UBNT-SEC-011")
        .unwrap();
    assert!(rule
        .evaluate(
            &SnapshotView::new(&s, &d, &sites, &p),
            &RuleConfig::default()
        )
        .is_empty());
}
#[test]
fn topology_matches_station_mac_ospf_and_reciprocal_arp() {
    let (mut s, d, sites, p) = fixture("UBNT-RF-001", true);
    s.device_results[0]
        .facts
        .radio
        .as_mut()
        .unwrap()
        .stations
        .push(StationFacts {
            mac: Some("02:00:00:00:00:02".into()),
            ..Default::default()
        });
    s.device_results[1].facts.interfaces.push(InterfaceFacts {
        name: Some("ath0".into()),
        mac: Some("02-00-00-00-00-02".into()),
        ..Default::default()
    });
    s.device_results[0].facts.interfaces.push(InterfaceFacts {
        name: Some("eth0".into()),
        mac: Some("02:00:00:00:00:01".into()),
        ..Default::default()
    });
    s.device_results[0].facts.neighbors.push(NeighborFacts {
        mac: Some("02:00:00:00:00:02".into()),
        ..Default::default()
    });
    s.device_results[1].facts.neighbors.push(NeighborFacts {
        mac: Some("02:00:00:00:00:01".into()),
        ..Default::default()
    });
    s.device_results[0].facts.routing = Some(RoutingFacts {
        ospf_neighbors: vec![OspfNeighbor {
            address: Some("10.0.0.2".into()),
            state: Some(OspfState::Full),
            ..Default::default()
        }],
        ..Default::default()
    });
    let graph = nm_analyze::topology::infer(&SnapshotView::new(&s, &d, &sites, &p));
    assert_eq!(graph.edges.len(), 4);
    let json = serde_json::to_string(&graph).unwrap();
    let copy: Result<nm_analyze::topology::TopologyGraph, _> = serde_json::from_str(&json);
    assert_eq!(copy.unwrap(), graph);
}

#[test]
fn firmware_model_alias_and_station_distance_scope() {
    let (mut snapshot, mut devices, sites, profiles) = fixture("UBNT-SEC-010", true);
    devices[0].family = DeviceFamily::EdgeOs;
    snapshot.device_results[0].facts.system.platform = None;
    snapshot.device_results[0].facts.system.model = Some("EdgeRouter X 5-Port".into());
    snapshot.device_results[0].facts.system.firmware = Some("v2.0.8".into());
    let view = SnapshotView::new(&snapshot, &devices, &sites, &profiles);
    assert!(nm_analyze::runner::evaluate(&view, &RuleConfig::default())
        .iter()
        .any(|finding| finding.rule_id.as_str() == "UBNT-SEC-010"));

    let (mut snapshot, devices, sites, profiles) = fixture("UBNT-RF-009", true);
    snapshot.device_results[0]
        .facts
        .radio
        .as_mut()
        .unwrap()
        .mode = Some(RadioMode::Ap);
    let view = SnapshotView::new(&snapshot, &devices, &sites, &profiles);
    assert!(!nm_analyze::runner::evaluate(&view, &RuleConfig::default())
        .iter()
        .any(|finding| finding.rule_id.as_str() == "UBNT-RF-009"));
}
