use super::{
    airmax, chains, counters, flag, integer, load, mode, num, string, DeviceFacts, Duplex,
    InterfaceFacts, MemoryFacts, ParseError, RadioFacts, Result, ServiceFacts, SystemFacts, Value,
};
use nm_core::FirewallFacts;
use serde::{Deserialize, Serialize};
#[derive(Debug, Deserialize, Serialize)]
pub struct Dump {
    #[serde(default)]
    pub host: Value,
    #[serde(default)]
    pub wireless: Value,
    #[serde(default)]
    pub interfaces: Vec<Value>,
    #[serde(default)]
    pub services: Value,
    #[serde(default)]
    pub firewall: Value,
    #[serde(default)]
    pub genuine: Value,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}
#[allow(clippy::field_reassign_with_default)]
pub fn parse(bytes: &[u8]) -> Result<DeviceFacts, ParseError> {
    let dump: Dump = serde_json::from_slice(bytes)?;
    let h = &dump.host;
    let w = &dump.wireless;
    let mut f = DeviceFacts::default();
    f.system = SystemFacts {
        hostname: string(&h["hostname"]),
        netrole: string(&h["netrole"]),
        firmware: string(&h["fwversion"]),
        model: string(&h["devmodel"]),
        uptime_seconds: integer(&h["uptime"]),
        loadavg: load(&h["loadavg"]),
        memory: Some(MemoryFacts {
            total_bytes: integer(&h["totalram"]),
            free_bytes: integer(&h["freeram"]),
            ..MemoryFacts::default()
        }),
        cpu_load_pct: num(&h["cpuload"]),
        genuine: flag(&dump.genuine),
        ..SystemFacts::default()
    };
    if w.is_object() {
        f.radio = Some(RadioFacts {
            mac: string(&w["mac"]).or_else(|| string(&w["hwaddr"])),
            mcs: integer(&w["mcs"]),
            airtime_pct: Some(nm_core::AirtimeFacts {
                busy: num(&w["polling"]["airtime"]["busy"])
                    .or_else(|| num(&w["athstats"]["airtime"]["busy"]))
                    .and_then(|n| n.to_string().parse::<f32>().ok())
                    .filter(|n| n.is_finite()),
                ..nm_core::AirtimeFacts::default()
            })
            .filter(|a| a.busy.is_some()),
            mode: mode(&w["mode"]),
            ssid: string(&w["essid"]),
            frequency_mhz: integer(&w["frequency"]),
            channel_width_mhz: integer(&w["chwidth"]),
            tx_power_dbm: integer(&w["txpower"]),
            signal_dbm: integer(&w["signal"]),
            noise_floor_dbm: integer(&w["noisef"]),
            ccq_pct: integer(&w["ccq"]),
            tx_rate_mbps: num(&w["txrate"])
                .and_then(|n| n.to_string().parse::<f32>().ok())
                .filter(|n| n.is_finite()),
            rx_rate_mbps: num(&w["rxrate"])
                .and_then(|n| n.to_string().parse::<f32>().ok())
                .filter(|n| n.is_finite()),
            chains: chains(&w["chainrssi"]),
            distance_m: integer(&w["distance"]),
            polling_enabled: flag(&w["polling"]["enabled"]),
            airmax: airmax(&w["polling"]),
            ..RadioFacts::default()
        });
    }
    f.interfaces = dump
        .interfaces
        .iter()
        .map(|i| {
            let s = &i["status"];
            InterfaceFacts {
                name: string(&i["ifname"]),
                mac: string(&i["hwaddr"]),
                admin_up: flag(&i["enabled"]),
                oper_up: flag(&s["plugged"]),
                speed_mbps: integer(&s["speed"]),
                duplex: match s["duplex"].as_str() {
                    Some("full") => Some(Duplex::Full),
                    Some("half") => Some(Duplex::Half),
                    _ => None,
                },
                counters: Some(counters(s)),
                ..InterfaceFacts::default()
            }
        })
        .collect();
    let service = |name: &str| {
        let v = &dump.services[name];
        ServiceFacts {
            enabled: flag(v).or_else(|| flag(&v["enabled"])),
            ..ServiceFacts::default()
        }
    };
    f.services.dhcp_client = service("dhcpc");
    f.services.dhcp_server = service("dhcpd");
    f.services.pppoe = service("pppoe");
    if let Some(fields) = dump.firewall.as_object() {
        f.firewall = Some(FirewallFacts {
            enabled: flag(&dump.firewall["enabled"]),
            vendor_fields: fields.clone(),
            ..FirewallFacts::default()
        });
    }
    // Preserve vendor fields that lack stable typed interpretations in raw JSON.
    Ok(f)
}
