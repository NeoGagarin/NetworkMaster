use super::parse;
use async_trait::async_trait;
use nm_collect::{
    allowlist::airos,
    scrub::scrub_secrets,
    ssh::{hostkeys::HostKeyStore, SshError, SshTransport},
    Action, CollectCtx, CollectError, CollectionPlan, Collector, PlannedAction, SshCommand,
    Transport,
};
use nm_core::{
    ArtifactKind, Coverage, Device, DeviceFacts, DeviceFamily, DeviceResult, DeviceRole,
    InterfaceFacts, Outcome, RadioFacts, RawArtifact, SystemFacts,
};
use nm_store::{repo::ProfileRepo, Db};
use sha2::{Digest, Sha256};
use std::result::Result;
use std::{collections::BTreeMap, sync::Arc};

pub struct AirOsCollector {
    db: Db,
    transport: SshTransport,
}
impl AirOsCollector {
    pub fn new(db: Db) -> Self {
        Self {
            transport: SshTransport::new(Arc::new(HostKeyStore::new(db.clone()))),
            db,
        }
    }
}
pub fn commands(device: &Device) -> Vec<SshCommand> {
    airos::ALL
        .iter()
        .copied()
        .filter(|c| {
            *c != airos::WSTALIST || device.role.is_none() || device.role == Some(DeviceRole::Ap)
        })
        .collect()
}
pub fn artifact_name(command: SshCommand) -> &'static str {
    match command {
        airos::VERSION => "version.txt",
        airos::BOARD_INFO => "board-info.txt",
        airos::UPTIME => "uptime.txt",
        airos::FREE => "free.txt",
        airos::LOADAVG => "loadavg.txt",
        airos::MCA_STATUS => "mca-status.txt",
        airos::MCA_DUMP => "mca-dump.json",
        airos::WSTALIST => "wstalist.json",
        airos::IWCONFIG => "iwconfig.txt",
        airos::IFCONFIG => "ifconfig.txt",
        airos::NET_DEV => "proc-net-dev.txt",
        airos::SYSTEM_CFG => "system.cfg",
        airos::BRCTL => "brctl.txt",
        airos::ARP => "arp.txt",
        _ => unreachable!("only airOS allowlist commands"),
    }
}
pub fn empty_result(device: &Device) -> DeviceResult {
    DeviceResult {
        device_id: device.id,
        outcome: Outcome::Ok,
        facts: DeviceFacts::default(),
        raw: vec![],
        coverage: Coverage {
            expected: commands(device).iter().map(|c| c.as_str().into()).collect(),
            ..Coverage::default()
        },
    }
}

/// Parse in precedence order, independently of command execution order.
pub fn parse_artifacts(raw: &[RawArtifact], coverage: &mut Coverage) -> DeviceFacts {
    let map: BTreeMap<_, _> = raw
        .iter()
        .map(|r| (r.name.as_str(), r.bytes.as_slice()))
        .collect();
    let mut facts = DeviceFacts::default();
    for command in [
        airos::VERSION,
        airos::BOARD_INFO,
        airos::UPTIME,
        airos::FREE,
        airos::LOADAVG,
        airos::SYSTEM_CFG,
        airos::IWCONFIG,
        airos::IFCONFIG,
        airos::NET_DEV,
        airos::ARP,
        airos::BRCTL,
        airos::MCA_STATUS,
        airos::MCA_DUMP,
        airos::WSTALIST,
    ] {
        let Some(bytes) = map.get(artifact_name(command)) else {
            continue;
        };
        let parsed = match command {
            airos::VERSION => parse::version::parse(bytes).map(|v| DeviceFacts {
                system: SystemFacts {
                    firmware: Some(v.version),
                    platform: Some(v.platform),
                    soc: Some(v.soc),
                    firmware_build: Some(v.build),
                    ..SystemFacts::default()
                },
                ..DeviceFacts::default()
            }),
            airos::BOARD_INFO => parse::board_info::parse(bytes).map(|v| DeviceFacts {
                system: SystemFacts {
                    model: v.name.or(v.shortname),
                    board_id: v.sysid,
                    ..SystemFacts::default()
                },
                ..DeviceFacts::default()
            }),
            airos::UPTIME => parse::system::uptime(bytes),
            airos::FREE => parse::system::free(bytes),
            airos::LOADAVG => parse::system::loadavg(bytes),
            airos::SYSTEM_CFG => parse::system_cfg::parse(bytes),
            airos::IWCONFIG => parse::iwconfig::parse(bytes),
            airos::IFCONFIG => parse::ifconfig::parse(bytes).map(|interfaces| DeviceFacts {
                interfaces,
                ..DeviceFacts::default()
            }),
            airos::NET_DEV => parse::proc_net_dev::parse(bytes).map(|interfaces| DeviceFacts {
                interfaces,
                ..DeviceFacts::default()
            }),
            airos::ARP => parse::arp::parse(bytes).map(|neighbors| DeviceFacts {
                neighbors,
                ..DeviceFacts::default()
            }),
            airos::MCA_STATUS => parse::mca_status::parse(bytes).map(|s| s.facts),
            airos::MCA_DUMP => parse::mca_dump::parse(bytes),
            airos::WSTALIST => parse::wstalist::parse(bytes).map(|stations| DeviceFacts {
                radio: Some(RadioFacts {
                    stations,
                    ..RadioFacts::default()
                }),
                ..DeviceFacts::default()
            }),
            airos::BRCTL => parse::text(bytes).map(|_| DeviceFacts::default()),
            _ => unreachable!(),
        };
        match parsed {
            Ok(mut parsed) => {
                // Merge interfaces by name, preserving fallback counters/MACs. A merge
                // failure is device-input driven and must never panic the scan; the
                // earlier observation is kept and the error is recorded.
                for incoming in parsed.interfaces.drain(..) {
                    if let Some(existing) = facts
                        .interfaces
                        .iter_mut()
                        .find(|i| i.name == incoming.name)
                    {
                        match merge_interface_facts(existing, &incoming) {
                            Ok(merged) => *existing = merged,
                            Err(error) => {
                                coverage.errors.insert(
                                    format!(
                                        "{}:interface:{}",
                                        command.as_str(),
                                        incoming.name.as_deref().unwrap_or("?")
                                    ),
                                    error.to_string(),
                                );
                            }
                        }
                    } else {
                        facts.interfaces.push(incoming);
                    }
                    coverage
                        .sources
                        .insert("interfaces".into(), command.as_str().into());
                }
                record_sources(coverage, &parsed, command);
                parse::merge(&mut facts, &parsed);
            }
            Err(e) => {
                coverage.collected.retain(|c| c != command.as_str());
                if !coverage.missing.iter().any(|c| c == command.as_str()) {
                    coverage.missing.push(command.as_str().into());
                }
                coverage
                    .errors
                    .insert(command.as_str().into(), e.to_string());
            }
        }
    }
    crate::edgeos::parse::infer_wan(&mut facts);
    facts
}
/// Record which command populated each non-empty top-level facts section.
fn record_sources(coverage: &mut Coverage, parsed: &DeviceFacts, command: SshCommand) {
    let (Ok(value), Ok(default)) = (
        serde_json::to_value(parsed),
        serde_json::to_value(DeviceFacts::default()),
    ) else {
        return;
    };
    let Some(sections) = value.as_object() else {
        return;
    };
    for (section, v) in sections {
        if !v.is_null() && v != &default[section] {
            coverage.sources.insert(
                if section == "radio" && command == airos::WSTALIST {
                    "radio.stations".into()
                } else {
                    section.clone()
                },
                command.as_str().into(),
            );
        }
    }
}

/// Overlay `incoming` onto `existing` field by field, keeping observations the
/// later parser did not provide. Fails instead of panicking when the two
/// serializations cannot be reconciled.
pub(crate) fn merge_interface_facts(
    existing: &InterfaceFacts,
    incoming: &InterfaceFacts,
) -> Result<InterfaceFacts, serde_json::Error> {
    let mut value = serde_json::to_value(existing)?;
    merge_interface(&mut value, &serde_json::to_value(incoming)?);
    serde_json::from_value(value)
}

pub(crate) fn merge_interface(t: &mut serde_json::Value, i: &serde_json::Value) {
    if let (Some(t), Some(i)) = (t.as_object_mut(), i.as_object()) {
        for (k, v) in i {
            if v.is_null() || v.as_array().is_some_and(Vec::is_empty) {
                continue;
            }
            if v.is_object() {
                let target = t.entry(k).or_insert(serde_json::json!({}));
                if !target.is_object() {
                    *target = serde_json::json!({});
                }
                merge_interface(target, v);
            } else {
                t.insert(k.clone(), v.clone());
            }
        }
    }
}

#[async_trait]
impl Collector for AirOsCollector {
    fn family(&self) -> DeviceFamily {
        DeviceFamily::AirOs
    }
    fn plan(&self, device: &Device) -> CollectionPlan {
        CollectionPlan(
            commands(device)
                .into_iter()
                .map(|c| PlannedAction {
                    transport: Transport::Ssh,
                    target: device.management.clone(),
                    action: Action::SshCommand(c),
                })
                .collect(),
        )
    }
    async fn collect(
        &self,
        ctx: &CollectCtx,
        device: &Device,
    ) -> Result<DeviceResult, CollectError> {
        let mut result = empty_result(device);
        ctx.progress(device.id, "connecting".into()).await;
        let profile = device
            .credential_profile
            .and_then(|id| ProfileRepo::new(&self.db).get(id).ok().flatten());
        let Some(profile) = profile else {
            result.outcome = Outcome::AuthFailed;
            result
                .coverage
                .missing
                .clone_from(&result.coverage.expected);
            result
                .coverage
                .errors
                .insert("ssh".into(), "no credential profile".into());
            return Ok(result);
        };
        let mut session = match self.transport.connect(ctx, device, &profile).await {
            Ok(s) => s,
            Err(error) => {
                ctx.audit
                    .append(nm_core::AuditEvent {
                        ts: nm_core::Timestamp::now(),
                        actor: nm_core::Actor::Collector,
                        action: nm_core::AuditAction::SshConnect,
                        target: device.id.to_string(),
                        detail: serde_json::json!({"error":error.to_string(),"accepted":false}),
                        bytes_in: 0,
                        bytes_out: 0,
                    })
                    .await
                    .map_err(|e| CollectError::Unreachable(e.to_string()))?;
                result.outcome = match error {
                    SshError::AuthFailed => Outcome::AuthFailed,
                    SshError::Cancelled => Outcome::Cancelled,
                    _ => Outcome::Unreachable,
                };
                if matches!(error, SshError::HostKeyChanged { .. }) {
                    result.facts.system.ssh_host_key_changed = Some(true);
                }
                if let SshError::LegacyAlgorithmsRequired(algorithms) = &error {
                    ctx.progress(device.id, "legacy SSH opt-in required".into())
                        .await;
                    ctx.legacy_required(device.id, algorithms.clone()).await;
                }
                result
                    .coverage
                    .missing
                    .clone_from(&result.coverage.expected);
                result
                    .coverage
                    .errors
                    .insert("ssh".into(), error.to_string());
                return Ok(result);
            }
        };
        for command in commands(device) {
            if ctx.cancel.is_cancelled() {
                result.outcome = Outcome::Cancelled;
                break;
            }
            ctx.progress(device.id, format!("running {}", command.as_str()))
                .await;
            match session.run(command).await {
                Ok(output) => {
                    let (bytes, removed) =
                        scrub_secrets(DeviceFamily::AirOs, artifact_name(command), &output.stdout);
                    result.raw.push(RawArtifact {
                        kind: if matches!(command, airos::MCA_DUMP | airos::WSTALIST) {
                            ArtifactKind::Json
                        } else if command == airos::SYSTEM_CFG {
                            ArtifactKind::Config
                        } else {
                            ArtifactKind::Text
                        },
                        name: artifact_name(command).into(),
                        sha256: Sha256::digest(&bytes).into(),
                        bytes,
                        redacted: true,
                    });
                    if output.exit == Some(0) && !output.truncated {
                        result.coverage.collected.push(command.as_str().into());
                    } else {
                        result.coverage.errors.insert(
                            command.as_str().into(),
                            format!("exit {:?}; truncated {}", output.exit, output.truncated),
                        );
                        result.coverage.missing.push(command.as_str().into());
                    }
                    // Parse original config only transiently for default-community detection.
                    if command == airos::SYSTEM_CFG {
                        if let Ok(config) = parse::system_cfg::parse(&output.stdout) {
                            result.facts.services.snmp = config.services.snmp;
                            result.facts.config = config.config;
                        }
                    }
                    let _ = removed;
                }
                Err(error) => {
                    result.coverage.missing.push(command.as_str().into());
                    result
                        .coverage
                        .errors
                        .insert(command.as_str().into(), error.to_string());
                    if matches!(error, SshError::Cancelled) {
                        result.outcome = Outcome::Cancelled;
                    }
                    // A timed out channel may still be executing remotely. End
                    // this session rather than overlap it with another command.
                    break;
                }
            }
            let snmp = result.facts.services.snmp.clone();
            let config = result.facts.config.clone();
            result.facts = parse_artifacts(&result.raw, &mut result.coverage);
            if snmp.community_is_default.is_some() {
                result.facts.services.snmp.community_is_default = snmp.community_is_default;
            }
            if let Some(config) = config {
                result.facts.config = Some(config);
            }
            result.facts.system.ssh_legacy_algorithms = Some(session.legacy);
            ctx.save_partial(&result);
        }
        for expected in &result.coverage.expected {
            if !result.coverage.collected.contains(expected)
                && !result.coverage.missing.contains(expected)
            {
                result.coverage.missing.push(expected.clone());
            }
        }
        if result.outcome != Outcome::Cancelled && !result.coverage.missing.is_empty() {
            result.outcome = Outcome::Partial(result.coverage.missing.clone());
        }
        let _ = session.close().await;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_keeps_earlier_observations_and_overlays_new_ones() {
        let existing = InterfaceFacts {
            name: Some("eth0".into()),
            mac: Some("02:00:00:00:00:01".into()),
            speed_mbps: Some(100),
            ..InterfaceFacts::default()
        };
        let incoming = InterfaceFacts {
            name: Some("eth0".into()),
            speed_mbps: Some(1000),
            oper_up: Some(true),
            ..InterfaceFacts::default()
        };
        let merged = merge_interface_facts(&existing, &incoming).unwrap();
        assert_eq!(merged.mac.as_deref(), Some("02:00:00:00:00:01"));
        assert_eq!(merged.speed_mbps, Some(1000));
        assert_eq!(merged.oper_up, Some(true));
    }

    #[test]
    fn irreconcilable_merge_is_an_error_not_a_panic() {
        // A parser emitting a shape the facts type cannot hold must surface as an
        // error that the collector records in coverage, never as a panic.
        let mut value = serde_json::to_value(InterfaceFacts::default()).unwrap();
        merge_interface(&mut value, &serde_json::json!({"speed_mbps": "fast"}));
        assert!(serde_json::from_value::<InterfaceFacts>(value).is_err());
    }
}
