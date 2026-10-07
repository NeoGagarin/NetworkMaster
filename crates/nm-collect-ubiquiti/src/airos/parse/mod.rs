use std::result::Result;
pub mod arp;
pub mod board_info;
pub mod ifconfig;
pub mod iwconfig;
pub mod mca_dump;
pub mod mca_status;
pub mod proc_net_dev;
pub mod system;
pub mod system_cfg;
pub mod version;
pub mod wstalist;
use nm_core::{
    AirMaxFacts, ChainSignal, ConfigFormat, DeviceFacts, DeviceFamily, Duplex, InterfaceCounters,
    InterfaceFacts, LoadAverage, MemoryFacts, NeighborFacts, RadioFacts, RadioMode, RedactedConfig,
    RemoteRadioFacts, RouteFacts, RoutingFacts, ServiceFacts, ServicesFacts, SnmpFacts,
    StationFacts, SystemFacts,
};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct ParseError(pub String);
impl From<serde_json::Error> for ParseError {
    fn from(e: serde_json::Error) -> Self {
        Self(e.to_string())
    }
}
pub fn text(bytes: &[u8]) -> Result<&str, ParseError> {
    std::str::from_utf8(bytes).map_err(|e| ParseError(e.to_string()))
}
pub fn key_values(bytes: &[u8]) -> Result<BTreeMap<String, String>, ParseError> {
    let result: BTreeMap<_, _> = text(bytes)?
        .lines()
        .flat_map(|l| l.split(','))
        .filter_map(|l| l.trim().split_once('='))
        .map(|(k, v)| (k.trim().into(), v.trim().into()))
        .collect();
    if result.is_empty() {
        Err(ParseError("no key=value observations".into()))
    } else {
        Ok(result)
    }
}
pub(super) fn num(v: &Value) -> Option<f64> {
    v.as_f64().or_else(|| v.as_str()?.trim().parse().ok())
}
pub(super) fn integer<T: TryFrom<i64>>(v: &Value) -> Option<T> {
    let n = v
        .as_i64()
        .or_else(|| v.as_u64().and_then(|n| i64::try_from(n).ok()))
        .or_else(|| v.as_str()?.trim().parse().ok())?;
    T::try_from(n).ok()
}
pub(super) fn string(v: &Value) -> Option<String> {
    v.as_str().map(str::to_owned).filter(|s| !s.is_empty())
}
pub(super) fn flag(v: &Value) -> Option<bool> {
    v.as_bool()
        .or_else(|| match v.as_str()? {
            "enabled" | "true" | "1" | "yes" | "up" => Some(true),
            "disabled" | "false" | "0" | "no" | "down" => Some(false),
            _ => None,
        })
        .or_else(|| v.as_u64().map(|n| n != 0))
}
pub(super) fn mode(v: &Value) -> Option<RadioMode> {
    match v.as_str()? {
        "ap" | "AP" | "aprepeater" | "3" => Some(RadioMode::Ap),
        "sta" | "station" | "1" => Some(RadioMode::Station),
        "ptp-master" => Some(RadioMode::PtpMaster),
        "ptp-slave" => Some(RadioMode::PtpSlave),
        _ => None,
    }
}
pub(super) fn chains(v: &Value) -> Vec<ChainSignal> {
    let values: Vec<_> = if let Some(a) = v.as_array() {
        a.clone()
    } else if let Some(s) = v.as_str() {
        s.split([' ', ':', ',', ';'])
            .filter(|s| !s.is_empty())
            .map(|s| Value::String(s.into()))
            .collect()
    } else {
        vec![]
    };
    values
        .iter()
        .enumerate()
        .filter_map(|(i, v)| {
            Some(ChainSignal {
                chain: u8::try_from(i).ok(),
                rssi_dbm: Some(integer(v)?),
            })
        })
        .collect()
}
pub(super) fn airmax(v: &Value) -> Option<AirMaxFacts> {
    v.as_object()?;
    Some(AirMaxFacts {
        quality_pct: integer(&v["quality"]),
        capacity_pct: integer(&v["capacity"]),
        priority: integer(&v["priority"]),
    })
}
pub(super) fn counters(v: &Value) -> InterfaceCounters {
    InterfaceCounters {
        rx_bytes: integer(&v["rx_bytes"]),
        tx_bytes: integer(&v["tx_bytes"]),
        rx_packets: integer(&v["rx_packets"]),
        tx_packets: integer(&v["tx_packets"]),
        rx_errors: integer(&v["rx_errors"]),
        tx_errors: integer(&v["tx_errors"]),
        rx_dropped: integer(&v["rx_dropped"]),
        tx_dropped: integer(&v["tx_dropped"]),
    }
}
pub(crate) fn load(v: &Value) -> Option<LoadAverage> {
    let values = if let Some(s) = v.as_str() {
        s.split_whitespace()
            .take(3)
            .map(|s| s.parse().ok())
            .collect::<Vec<Option<f64>>>()
    } else {
        v.as_array()?.iter().take(3).map(num).collect()
    };
    Some(LoadAverage {
        one_min: values.first().copied().flatten(),
        five_min: values.get(1).copied().flatten(),
        fifteen_min: values.get(2).copied().flatten(),
    })
}
pub fn merge(target: &mut DeviceFacts, incoming: &DeviceFacts) {
    fn overlay(target: &mut Value, incoming: &Value) {
        match (target, incoming) {
            (Value::Object(t), Value::Object(i)) => {
                for (key, value) in i {
                    overlay(t.entry(key.clone()).or_insert(Value::Null), value);
                }
            }
            (t, Value::Array(i)) if !i.is_empty() => *t = Value::Array(i.clone()),
            (t, i) if !i.is_null() && !i.is_array() => *t = i.clone(),
            _ => {}
        }
    }
    let mut value = serde_json::to_value(&*target).expect("facts serialize");
    overlay(
        &mut value,
        &serde_json::to_value(incoming).expect("facts serialize"),
    );
    *target = serde_json::from_value(value).expect("facts overlay preserves types");
}
