use crate::{CredentialProfileId, DeviceId, SiteId};
use serde::{Deserialize, Serialize};
use std::{fmt, net::IpAddr, str::FromStr};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    pub id: DeviceId,
    pub display_name: String,
    pub management: ManagementAddress,
    pub vendor: Vendor,
    pub family: DeviceFamily,
    pub role: Option<DeviceRole>,
    pub site: Option<SiteId>,
    pub credential_profile: Option<CredentialProfileId>,
    pub source: EnrollmentSource,
    pub enrolled: bool,
    pub tags: Vec<String>,
}
impl Device {
    pub fn is_enrolled(&self) -> bool {
        self.enrolled
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ManagementAddress {
    pub host: HostOrIp,
    pub port: Option<u16>,
}
impl fmt::Display for ManagementAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.host, self.port) {
            (HostOrIp::Ip(IpAddr::V6(ip)), Some(port)) => write!(f, "[{ip}]:{port}"),
            (host, Some(port)) => write!(f, "{host}:{port}"),
            (host, None) => host.fmt(f),
        }
    }
}
impl FromStr for ManagementAddress {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(ip) = s.parse::<IpAddr>() {
            return Ok(Self {
                host: HostOrIp::Ip(ip),
                port: None,
            });
        }
        if let Ok(addr) = s.parse::<std::net::SocketAddr>() {
            if addr.port() == 0 {
                return Err("port must be nonzero".into());
            }
            return Ok(Self {
                host: HostOrIp::Ip(addr.ip()),
                port: Some(addr.port()),
            });
        }
        let (host, port) = if let Some((host, port)) = s.rsplit_once(':') {
            let port = port.parse::<u16>().map_err(|_| "invalid port")?;
            if port == 0 {
                return Err("port must be nonzero".into());
            }
            (host, Some(port))
        } else {
            (s, None)
        };
        if host.is_empty()
            || host.len() > 253
            || host.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
        {
            return Err("expected an IP address or DNS hostname, optionally with a port".into());
        }
        Ok(Self {
            host: HostOrIp::Hostname(host.to_ascii_lowercase()),
            port,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HostOrIp {
    Hostname(String),
    Ip(IpAddr),
}
impl fmt::Display for HostOrIp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hostname(host) => f.write_str(host),
            Self::Ip(ip) => ip.fmt(f),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Vendor {
    Ubiquiti,
    Unknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DeviceFamily {
    AirOs,
    EdgeOs,
    EdgeSwitch,
    UniFi,
    Uisp,
    Unknown,
}
impl DeviceFamily {
    pub fn default_port(&self) -> u16 {
        match self {
            Self::UniFi | Self::Uisp => 443,
            Self::EdgeSwitch => 161,
            _ => 22,
        }
    }
}
impl FromStr for DeviceFamily {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "airos" => Ok(Self::AirOs),
            "edgeos" => Ok(Self::EdgeOs),
            "edgeswitch" => Ok(Self::EdgeSwitch),
            "unifi" => Ok(Self::UniFi),
            "uisp" => Ok(Self::Uisp),
            "unknown" => Ok(Self::Unknown),
            _ => Err(format!("unknown device family: {s}")),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceRole {
    Ap,
    Station,
    Ptp,
    Router,
    Switch,
    Gateway,
    Controller,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnrollmentSource {
    Manual,
    UispImport,
    UniFiImport,
    Discovery,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Site {
    pub id: SiteId,
    pub name: String,
    pub notes: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_addresses_without_resolving_them() {
        for s in [
            "192.0.2.1",
            "192.0.2.1:22",
            "::1",
            "[::1]:22",
            "router.example:443",
        ] {
            assert_eq!(s.parse::<ManagementAddress>().unwrap().to_string(), s);
        }
        for s in [
            "",
            "bad host",
            "http://router",
            "router:0",
            "router:65536",
            "-router",
        ] {
            assert!(s.parse::<ManagementAddress>().is_err(), "{s}");
        }
    }
}
