use super::parse;
use async_trait::async_trait;
use nm_collect::{
    allowlist::edgeos,
    scrub::scrub_secrets,
    ssh::{hostkeys::HostKeyStore, SshError, SshTransport},
    Action, CollectCtx, CollectError, CollectionPlan, Collector, PlannedAction, SshCommand,
    Transport,
};
use nm_core::{
    ArtifactKind, Coverage, Device, DeviceFacts, DeviceFamily, DeviceResult, Outcome, RawArtifact,
};
use nm_store::{repo::ProfileRepo, Db};
use sha2::{Digest, Sha256};
use std::result::Result;
use std::sync::Arc;

/// Pinned SSH collector restricted to the fixed `EdgeOS` operational allowlist.
pub struct EdgeOsCollector {
    db: Db,
    transport: SshTransport,
}
impl EdgeOsCollector {
    /// Use the shared database for profiles and pinned host keys.
    pub fn new(db: Db) -> Self {
        Self {
            transport: SshTransport::new(Arc::new(HostKeyStore::new(db.clone()))),
            db,
        }
    }
}
/// Full dry-run plan; configured protocol branches are resolved after collecting config.
pub fn commands(_device: &Device) -> Vec<SshCommand> {
    edgeos::ALL.to_vec()
}
/// Stable artifact filename for an allowlisted command.
pub fn artifact_name(command: SshCommand) -> &'static str {
    match command {
        edgeos::CONFIG_CMDS => "configuration.txt",
        edgeos::VERSION => "version.txt",
        edgeos::INTERFACES => "interfaces.txt",
        edgeos::IF_ETH_DETAIL => "ethernet-detail.txt",
        edgeos::ROUTE_SUMMARY => "route-summary.txt",
        edgeos::ROUTE => "routes.txt",
        edgeos::OSPF_NEIGHBOR => "ospf-neighbor.txt",
        edgeos::OSPF_INTERFACE => "ospf-interface.txt",
        edgeos::BGP_SUMMARY => "bgp-summary.txt",
        edgeos::OFFLOAD => "offload.txt",
        edgeos::DHCP_LEASES => "dhcp-leases.txt",
        edgeos::DHCP_STATS => "dhcp-stats.txt",
        edgeos::FW_STATS => "firewall-stats.txt",
        edgeos::NAT_STATS => "nat-stats.txt",
        edgeos::UPTIME => "uptime.txt",
        edgeos::LOADAVG => "loadavg.txt",
        edgeos::MEMINFO => "meminfo.txt",
        edgeos::NET_DEV => "proc-net-dev.txt",
        edgeos::ARP => "arp.txt",
        _ => unreachable!("only EdgeOS allowlist commands"),
    }
}
/// Initialize expected coverage without opening a connection.
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

/// Parse redacted artifacts in order, recording errors and retaining other observations.
pub fn parse_artifacts(raw: &[RawArtifact], coverage: &mut Coverage) -> DeviceFacts {
    let mut facts = DeviceFacts::default();
    for command in edgeos::ALL {
        let Some(a) = raw.iter().find(|a| a.name == artifact_name(*command)) else {
            continue;
        };
        let b = &a.bytes;
        let parsed = match *command {
            edgeos::CONFIG_CMDS => parse::config_tree::parse(b),
            edgeos::VERSION => parse::version(b),
            edgeos::INTERFACES => parse::interfaces(b),
            edgeos::IF_ETH_DETAIL => parse::if_eth_detail(b),
            edgeos::ROUTE_SUMMARY => parse::route_summary(b),
            edgeos::ROUTE => parse::route(b),
            edgeos::OSPF_NEIGHBOR => parse::ospf_neighbor(b),
            edgeos::OSPF_INTERFACE => parse::ospf_interface(b),
            edgeos::BGP_SUMMARY => parse::bgp_summary(b),
            edgeos::OFFLOAD => parse::offload(b),
            edgeos::DHCP_LEASES => parse::dhcp_leases(b),
            edgeos::DHCP_STATS => parse::dhcp_stats(b),
            edgeos::FW_STATS => parse::firewall_stats(b, false),
            edgeos::NAT_STATS => parse::firewall_stats(b, true),
            edgeos::UPTIME => crate::common::linux::uptime(b),
            edgeos::LOADAVG => crate::common::linux::loadavg(b),
            edgeos::MEMINFO => crate::common::linux::meminfo(b),
            edgeos::NET_DEV => crate::common::linux::net_dev(b).map(|interfaces| DeviceFacts {
                interfaces,
                ..DeviceFacts::default()
            }),
            edgeos::ARP => crate::common::linux::arp(b).map(|neighbors| DeviceFacts {
                neighbors,
                ..DeviceFacts::default()
            }),
            _ => unreachable!(),
        };
        match parsed {
            Ok(mut p) => {
                for incoming in p.interfaces.drain(..) {
                    if let Some(existing) = facts
                        .interfaces
                        .iter_mut()
                        .find(|i| i.name == incoming.name)
                    {
                        match crate::airos::collector::merge_interface_facts(existing, &incoming) {
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
                }
                if let Some(d) = p.dhcp.take() {
                    for pool in d.pools {
                        let pools = &mut facts.dhcp.get_or_insert_with(Default::default).pools;
                        if let Some(old) = pools.iter_mut().find(|p| p.name == pool.name) {
                            if pool.size.is_some() {
                                old.size = pool.size;
                            }
                            if pool.leased.is_some() {
                                old.leased = pool.leased;
                            }
                            if pool.available.is_some() {
                                old.available = pool.available;
                            }
                        } else {
                            pools.push(pool);
                        }
                    }
                }
                if let Some(f) = p.firewall.take() {
                    let old = facts.firewall.get_or_insert_with(Default::default);
                    for set in f.rule_sets {
                        if let Some(o) = old.rule_sets.iter_mut().find(|s| s.name == set.name) {
                            for r in set.rules {
                                if let Some(v) = o.rules.iter_mut().find(|v| v.number == r.number) {
                                    v.packets = r.packets;
                                    v.bytes = r.bytes;
                                } else {
                                    o.rules.push(r);
                                }
                            }
                        } else {
                            old.rule_sets.push(set);
                        }
                    }
                    old.nat_rules.extend(f.nat_rules);
                }
                crate::airos::parse::merge(&mut facts, &p);
                coverage
                    .sources
                    .insert(a.name.clone(), command.as_str().into());
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
    parse::infer_wan(&mut facts);
    facts
}

#[async_trait]
impl Collector for EdgeOsCollector {
    fn family(&self) -> DeviceFamily {
        DeviceFamily::EdgeOs
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
        let mut tree: Option<parse::config_tree::ConfigTree> = None;
        for command in commands(device) {
            let branch = match command {
                edgeos::OSPF_NEIGHBOR | edgeos::OSPF_INTERFACE => Some("ospf"),
                edgeos::BGP_SUMMARY => Some("bgp"),
                _ => None,
            };
            if let Some(protocol) = branch {
                if tree
                    .as_ref()
                    .is_some_and(|t| !t.contains(&["protocols", protocol]))
                {
                    result
                        .coverage
                        .skipped
                        .insert(command.as_str().into(), "skipped-by-config".into());
                    continue;
                }
            }
            if ctx.cancel.is_cancelled() {
                result.outcome = Outcome::Cancelled;
                break;
            }
            ctx.progress(device.id, format!("running {}", command.as_str()))
                .await;
            match session.run(command).await {
                Ok(output) => {
                    let (bytes, removed) = if command == edgeos::CONFIG_CMDS {
                        let complete = output.exit == Some(0) && !output.truncated;
                        let parsed = complete
                            .then(|| parse::config_tree::parse(&output.stdout).ok())
                            .flatten();
                        tree = complete
                            .then(|| parse::config_tree::ConfigTree::parse(&output.stdout).ok())
                            .flatten();
                        if let Some(config) = parsed {
                            result.facts.services.snmp = config.services.snmp;
                            result.facts.config = config.config;
                        }
                        // Never retain original configuration, even if parsing fails.
                        (
                            tree.as_ref()
                                .map(|t| t.serialize().into_bytes())
                                .unwrap_or_default(),
                            tree.as_ref().map_or(0, |t| t.secrets_removed),
                        )
                    } else {
                        scrub_secrets(DeviceFamily::EdgeOs, artifact_name(command), &output.stdout)
                    };
                    result.raw.push(RawArtifact {
                        kind: if command == edgeos::CONFIG_CMDS {
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
                && !result.coverage.skipped.contains_key(expected)
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
