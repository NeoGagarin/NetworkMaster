use super::{
    chains, flag, integer, key_values, load, mode, num, string, BTreeMap, ChainSignal, DeviceFacts,
    InterfaceFacts, MemoryFacts, ParseError, RadioFacts, Result, SystemFacts, Value,
};
use serde::Serialize;
#[derive(Debug, Serialize)]
pub struct Status {
    pub facts: DeviceFacts,
    pub values: BTreeMap<String, String>,
}
#[allow(clippy::field_reassign_with_default)]
pub fn parse(bytes: &[u8]) -> Result<Status, ParseError> {
    let values = key_values(bytes)?;
    let value = |names: &[&str]| {
        names
            .iter()
            .find_map(|n| values.get(*n))
            .map_or(Value::Null, |s| Value::String(s.clone()))
    };
    let mut facts = DeviceFacts::default();
    facts.system = SystemFacts {
        hostname: string(&value(&["deviceName", "hostname"])),
        firmware: string(&value(&["firmwareVersion"])),
        uptime_seconds: integer(&value(&["uptime"])),
        loadavg: load(&value(&["loadavg"])),
        memory: Some(MemoryFacts {
            total_bytes: integer::<u64>(&value(&["memTotal"])).and_then(|n| n.checked_mul(1024)),
            free_bytes: integer::<u64>(&value(&["memFree"])).and_then(|n| n.checked_mul(1024)),
            ..MemoryFacts::default()
        }),
        ..SystemFacts::default()
    };
    let mut radio = RadioFacts {
        mode: mode(&value(&["wlanOpmode"])),
        ssid: string(&value(&["ssid"])),
        frequency_mhz: integer(&value(&["freq"])),
        channel_width_mhz: integer(&value(&["chanbw"])),
        signal_dbm: integer(&value(&["signal"])),
        noise_floor_dbm: integer(&value(&["noise", "noisef"])),
        ccq_pct: integer(&value(&["ccq"])),
        tx_rate_mbps: num(&value(&["wlanTxRate", "txrate"]))
            .and_then(|n| n.to_string().parse::<f32>().ok())
            .filter(|n| n.is_finite()),
        rx_rate_mbps: num(&value(&["wlanRxRate", "rxrate"]))
            .and_then(|n| n.to_string().parse::<f32>().ok())
            .filter(|n| n.is_finite()),
        chains: chains(&value(&["chainrssi"])),
        ..RadioFacts::default()
    };
    if radio.chains.is_empty() {
        for i in 0..4u8 {
            if let Some(rssi) = integer(&value(&[
                &format!("chainrssi{i}"),
                &format!("chainrssi.{i}"),
            ])) {
                radio.chains.push(ChainSignal {
                    chain: Some(i),
                    rssi_dbm: Some(rssi),
                });
            }
        }
    }
    facts.radio = Some(radio);
    if values.contains_key("lanSpeed") || values.contains_key("lanPlugged") {
        facts.interfaces.push(InterfaceFacts {
            name: Some("eth0".into()),
            speed_mbps: integer(&value(&["lanSpeed"])),
            oper_up: flag(&value(&["lanPlugged"])),
            ..InterfaceFacts::default()
        });
    }
    Ok(Status { facts, values })
}
