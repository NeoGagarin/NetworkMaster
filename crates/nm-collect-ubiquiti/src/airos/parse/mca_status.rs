use super::{
    chains, flag, integer, key_values, mode, num, string, BTreeMap, ChainSignal, DeviceFacts,
    InterfaceFacts, MemoryFacts, ParseError, RadioFacts, Result, SystemFacts, Value,
};
use nm_core::{AirtimeFacts, Duplex, InterfaceCounters};
use serde::Serialize;
#[derive(Debug, Serialize)]
pub struct Status {
    pub facts: DeviceFacts,
    pub values: BTreeMap<String, String>,
}
/// Field names follow what real firmware prints. airOS 8 (`LiteBeam 5AC Gen2`,
/// 8.7.22) uses `chain0Signal`, `cpuUsage`, `airTime`, `txPower`, `distance`,
/// `lanSpeed=100Mbps-Full` and `lanRx*`/`wlanRx*` counters. `loadavg` there is
/// an integer scaled by 100 and is deliberately not mapped; `/proc/loadavg` is
/// always collected and is exact.
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
        model: string(&value(&["platform"])),
        firmware: string(&value(&["firmwareVersion"])),
        uptime_seconds: integer(&value(&["uptime"])),
        cpu_load_pct: num(&value(&["cpuUsage"])),
        memory: Some(MemoryFacts {
            total_bytes: integer::<u64>(&value(&["memTotal"])).and_then(|n| n.checked_mul(1024)),
            free_bytes: integer::<u64>(&value(&["memFree"])).and_then(|n| n.checked_mul(1024)),
            ..MemoryFacts::default()
        }),
        ..SystemFacts::default()
    };
    let f32_of = |v: Value| {
        num(&v)
            .and_then(|n| n.to_string().parse::<f32>().ok())
            .filter(|n| n.is_finite())
    };
    let mut radio = RadioFacts {
        mode: mode(&value(&["wlanOpmode"])),
        ssid: string(&value(&["essid", "ssid"])),
        mac: string(&value(&["deviceId", "wlanMac"])),
        frequency_mhz: integer(&value(&["freq"])),
        channel_width_mhz: integer(&value(&["chanbw"])),
        tx_power_dbm: integer(&value(&["txPower"])),
        signal_dbm: integer(&value(&["signal"])),
        noise_floor_dbm: integer(&value(&["noise", "noisef"])),
        ccq_pct: integer(&value(&["ccq"])),
        distance_m: integer(&value(&["distance"])),
        tx_rate_mbps: f32_of(value(&["wlanTxRate", "txrate"])),
        rx_rate_mbps: f32_of(value(&["wlanRxRate", "rxrate"])),
        airtime_pct: f32_of(value(&["airTime"])).map(|busy| AirtimeFacts {
            busy: Some(busy),
            ..AirtimeFacts::default()
        }),
        polling_enabled: flag(&value(&["wlanPolling"])),
        security: string(&value(&["security"])),
        chains: chains(&value(&["chainrssi"])),
        ..RadioFacts::default()
    };
    if radio.chains.is_empty() {
        for i in 0..4u8 {
            if let Some(rssi) = integer(&value(&[
                &format!("chain{i}Signal"),
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
    let counters = |prefix: &str| {
        let get = |suffix: &str| integer::<u64>(&value(&[&format!("{prefix}{suffix}")]));
        let c = InterfaceCounters {
            rx_bytes: get("RxBytes"),
            tx_bytes: get("TxBytes"),
            rx_packets: get("RxPackets"),
            tx_packets: get("TxPackets"),
            rx_errors: get("RxErrors"),
            tx_errors: get("TxErrors"),
            ..InterfaceCounters::default()
        };
        (c != InterfaceCounters::default()).then_some(c)
    };
    if values.contains_key("lanSpeed") || values.contains_key("lanPlugged") {
        let (speed, duplex) = lan_speed(&value(&["lanSpeed"]));
        facts.interfaces.push(InterfaceFacts {
            name: Some("eth0".into()),
            speed_mbps: speed,
            duplex,
            oper_up: flag(&value(&["lanPlugged"])),
            counters: counters("lan"),
            ..InterfaceFacts::default()
        });
    }
    if let Some(c) = counters("wlan") {
        facts.interfaces.push(InterfaceFacts {
            name: Some("ath0".into()),
            counters: Some(c),
            ..InterfaceFacts::default()
        });
    }
    Ok(Status { facts, values })
}
/// `lanSpeed` is `100Mbps-Full` on airOS 8 and a bare number on older builds.
fn lan_speed(v: &Value) -> (Option<u32>, Option<Duplex>) {
    let Some(s) = v.as_str() else {
        return (None, None);
    };
    let digits: String = s.chars().take_while(char::is_ascii_digit).collect();
    let speed = digits.parse().ok();
    let lower = s.to_ascii_lowercase();
    let duplex = if lower.contains("full") {
        Some(Duplex::Full)
    } else if lower.contains("half") {
        Some(Duplex::Half)
    } else {
        None
    };
    (speed, duplex)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lan_speed_forms() {
        assert_eq!(
            lan_speed(&Value::String("100Mbps-Full".into())),
            (Some(100), Some(Duplex::Full))
        );
        assert_eq!(lan_speed(&Value::String("1000".into())), (Some(1000), None));
        assert_eq!(lan_speed(&Value::Null), (None, None));
    }
}
