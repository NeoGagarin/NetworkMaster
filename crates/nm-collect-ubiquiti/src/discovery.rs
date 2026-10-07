pub mod parse;
use nm_collect::{net::LocalIface, NetFactory};
use nm_core::{
    Actor, AuditAction, AuditEvent, Device, DeviceFamily, DeviceId, EnrollmentSource, HostOrIp,
    ManagementAddress, Timestamp, Vendor,
};
use nm_store::AuditSink;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    io,
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredDevice {
    pub mac: Option<String>,
    pub ip: Option<Ipv4Addr>,
    pub hostname: Option<String>,
    pub model: Option<String>,
    pub firmware: Option<String>,
    pub essid: Option<String>,
    pub uptime: Option<u32>,
    pub wmode: Option<u8>,
    pub raw_tags: BTreeMap<u8, Vec<Vec<u8>>>,
}
impl DiscoveredDevice {
    pub fn candidate(&self) -> Option<Device> {
        let firmware = self.firmware.as_deref().unwrap_or("");
        let model = self.model.as_deref().unwrap_or("");
        let family = guess_family(firmware, model);
        Some(Device {
            id: DeviceId::new(),
            display_name: self.hostname.clone().unwrap_or_else(|| model.into()),
            management: ManagementAddress {
                host: HostOrIp::Ip(self.ip?.into()),
                port: None,
            },
            vendor: Vendor::Ubiquiti,
            family,
            role: None,
            site: None,
            credential_profile: None,
            source: EnrollmentSource::Discovery,
            enrolled: false,
            ssh_legacy_ok: false,
            interface_roles: std::collections::BTreeMap::default(),
            tags: vec![],
        })
    }
}
pub fn guess_family(firmware: &str, model: &str) -> DeviceFamily {
    if ["XW", "XC", "WA", "XM", "TI", "AF", "LTU"]
        .iter()
        .any(|p| firmware.starts_with(p) || model.starts_with(p))
    {
        DeviceFamily::AirOs
    } else if firmware.starts_with("ER-")
        || model.starts_with("ER-")
        || model.starts_with("EdgeRouter")
    {
        DeviceFamily::EdgeOs
    } else if model.starts_with("ES-") || firmware.starts_with("ES-") {
        DeviceFamily::EdgeSwitch
    } else if model.starts_with("US-") || firmware.starts_with("US-") {
        DeviceFamily::UniFi
    } else {
        DeviceFamily::Unknown
    }
}
pub async fn discover(
    net: &dyn NetFactory,
    audit: &AuditSink,
    iface: &LocalIface,
    window: Duration,
) -> io::Result<Vec<DiscoveredDevice>> {
    let socket = net.udp_bind(SocketAddr::from((iface.ipv4, 0))).await?;
    socket.set_broadcast(true)?;
    for destination in [Ipv4Addr::BROADCAST, iface.broadcast] {
        let bytes = socket.send_to(&[1, 0, 0, 0], (destination, 10001)).await?;
        audit
            .append(AuditEvent {
                ts: Timestamp::now(),
                actor: Actor::Collector,
                action: AuditAction::UdpProbe,
                target: format!("{destination}:10001"),
                detail: serde_json::json!({"interface":iface.name,"probe":[1,0,0,0]}),
                bytes_out: u64::try_from(bytes).unwrap_or(u64::MAX),
                bytes_in: 0,
            })
            .await
            .map_err(io::Error::other)?;
    }
    let deadline = tokio::time::Instant::now() + window;
    let mut bytes = vec![0u8; 65535];
    let mut found = BTreeMap::new();
    loop {
        match tokio::time::timeout_at(deadline, socket.recv_from(&mut bytes)).await {
            Ok(Ok((n, source))) => {
                if !matches!(source.ip(), std::net::IpAddr::V4(ip) if (u32::from(ip)&subnet_mask(iface)) == (u32::from(iface.ipv4)&subnet_mask(iface)))
                {
                    continue;
                }
                if let Ok(device) = parse::parse(&bytes[..n]) {
                    if let Some(ip) = device.ip {
                        found.insert((ip, device.mac.clone()), device);
                    }
                }
            }
            Ok(Err(e)) => return Err(e),
            Err(_) => break,
        }
    }
    audit.flush().await.map_err(io::Error::other)?;
    Ok(found.into_values().collect())
}
fn subnet_mask(iface: &LocalIface) -> u32 {
    u32::from(iface.netmask)
}
