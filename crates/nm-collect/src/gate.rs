use nm_core::{Device, DeviceId, HostOrIp, Outcome};
use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
};

#[derive(Debug, thiserror::Error)]
pub enum GateError {
    #[error("target {0} is not uniquely enrolled")]
    NotEnrolled(IpAddr),
}
#[derive(Clone, Debug)]
pub struct ResolutionFailure {
    pub device_id: DeviceId,
    pub reason: String,
    pub outcome: Outcome,
}
#[derive(Default, Debug)]
pub struct TargetGate {
    addresses: HashSet<IpAddr>,
    devices: HashMap<IpAddr, DeviceId>,
    failures: Vec<ResolutionFailure>,
}
impl TargetGate {
    /// Resolve enrolled hostnames once; connections use the resulting IPs, never DNS again.
    pub async fn new(inventory: &[Device]) -> Self {
        let mut gate = Self::default();
        let mut ambiguous = HashSet::new();
        let mut resolutions: HashMap<String, Result<Vec<IpAddr>, String>> = HashMap::new();
        for device in inventory.iter().filter(|d| d.is_enrolled()) {
            let addresses: Result<Vec<IpAddr>, String> = match &device.management.host {
                HostOrIp::Ip(ip) => Ok(vec![*ip]),
                HostOrIp::Hostname(host) => {
                    if let Some(cached) = resolutions.get(host) {
                        cached.clone()
                    } else {
                        let lookup = tokio::net::lookup_host((
                            host.as_str(),
                            device
                                .management
                                .port
                                .unwrap_or(device.family.default_port()),
                        ));
                        let result =
                            match tokio::time::timeout(std::time::Duration::from_secs(5), lookup)
                                .await
                            {
                                Ok(Ok(values)) => Ok(values.map(|v| v.ip()).collect()),
                                Ok(Err(error)) => Err(error.to_string()),
                                Err(_) => Err("DNS resolution timed out".into()),
                            };
                        resolutions.insert(host.clone(), result.clone());
                        result
                    }
                }
            };
            match addresses {
                Ok(mut addresses) if !addresses.is_empty() => {
                    addresses.sort_unstable();
                    addresses.dedup();
                    for ip in addresses {
                        if ambiguous.contains(&ip) {
                            gate.failures.push(ResolutionFailure {
                                device_id: device.id,
                                reason: format!("ambiguous enrolled address {ip}"),
                                outcome: Outcome::Unreachable,
                            });
                            continue;
                        }
                        if let Some(existing) = gate.devices.get(&ip) {
                            if *existing != device.id {
                                gate.failures.push(ResolutionFailure {
                                    device_id: *existing,
                                    reason: format!("ambiguous enrolled address {ip}"),
                                    outcome: Outcome::Unreachable,
                                });
                                gate.failures.push(ResolutionFailure {
                                    device_id: device.id,
                                    reason: format!("ambiguous enrolled address {ip}"),
                                    outcome: Outcome::Unreachable,
                                });
                                gate.devices.remove(&ip);
                                gate.addresses.remove(&ip);
                                ambiguous.insert(ip);
                            }
                        } else {
                            gate.addresses.insert(ip);
                            gate.devices.insert(ip, device.id);
                        }
                    }
                }
                result => gate.failures.push(ResolutionFailure {
                    device_id: device.id,
                    reason: result
                        .err()
                        .unwrap_or_else(|| "DNS returned no addresses".into()),
                    outcome: Outcome::Unreachable,
                }),
            }
        }
        gate
    }
    pub fn check(&self, ip: IpAddr) -> Result<DeviceId, GateError> {
        self.devices
            .get(&ip)
            .copied()
            .ok_or(GateError::NotEnrolled(ip))
    }
    pub fn addresses(&self) -> &HashSet<IpAddr> {
        &self.addresses
    }
    pub fn failures(&self) -> &[ResolutionFailure] {
        &self.failures
    }
}
