//! Shared Linux resource, counter and neighbor parsers.
pub use crate::airos::parse::arp::parse as arp;
pub use crate::airos::parse::proc_net_dev::parse as net_dev;
use crate::airos::parse::{text, ParseError};
use nm_core::{DeviceFacts, MemoryFacts, SystemFacts};
use serde_json::Value;
use std::result::Result;
/// Parse observed Linux load averages.
pub fn loadavg(bytes: &[u8]) -> Result<DeviceFacts, ParseError> {
    let s = text(bytes)?;
    let l = crate::airos::parse::load(&Value::String(s.into()))
        .filter(|l| l.one_min.is_some())
        .ok_or_else(|| ParseError("invalid load average".into()))?;
    Ok(DeviceFacts {
        system: SystemFacts {
            loadavg: Some(l),
            ..SystemFacts::default()
        },
        ..DeviceFacts::default()
    })
}
/// Parse the Linux free memory summary.
pub fn free(bytes: &[u8]) -> Result<DeviceFacts, ParseError> {
    let s = text(bytes)?;
    let line = s
        .lines()
        .find(|s| s.trim().starts_with("Mem:"))
        .ok_or_else(|| ParseError("missing memory row".into()))?;
    let cols: Vec<_> = line.split_whitespace().collect();
    let n = |i: usize| {
        cols.get(i)
            .and_then(|s| s.parse::<u64>().ok())
            .and_then(|n| n.checked_mul(1024))
    };
    Ok(DeviceFacts {
        system: SystemFacts {
            memory: Some(MemoryFacts {
                total_bytes: n(1),
                free_bytes: n(3),
                available_bytes: if cols.len() > 6 { n(6) } else { None },
            }),
            ..SystemFacts::default()
        },
        ..DeviceFacts::default()
    })
}
/// Parse Linux uptime into seconds.
pub fn uptime(bytes: &[u8]) -> Result<DeviceFacts, ParseError> {
    let s = text(bytes)?;
    let re = regex::Regex::new(r"up\s+(?:(\d+) days?,\s*)?(?:(\d+):(\d+)|(\d+) min)").unwrap();
    let c = re
        .captures(s)
        .ok_or_else(|| ParseError("unrecognized uptime".into()))?;
    let n = |i| {
        c.get(i)
            .and_then(|s| s.as_str().parse::<u64>().ok())
            .unwrap_or(0)
    };
    Ok(DeviceFacts {
        system: SystemFacts {
            uptime_seconds: Some(n(1) * 86400 + n(2) * 3600 + (n(3) + n(4)) * 60),
            ..SystemFacts::default()
        },
        ..DeviceFacts::default()
    })
}

/// Parse Linux meminfo, preferring `MemAvailable` when the kernel exposes it.
pub fn meminfo(bytes: &[u8]) -> Result<DeviceFacts, ParseError> {
    let text = text(bytes)?;
    let get = |name: &str| {
        text.lines().find_map(|l| {
            let (key, rest) = l.split_once(':')?;
            (key == name)
                .then(|| {
                    rest.split_whitespace()
                        .next()?
                        .parse::<u64>()
                        .ok()?
                        .checked_mul(1024)
                })
                .flatten()
        })
    };
    let total = get("MemTotal").ok_or_else(|| ParseError("missing MemTotal".into()))?;
    Ok(DeviceFacts {
        system: SystemFacts {
            memory: Some(MemoryFacts {
                total_bytes: Some(total),
                available_bytes: get("MemAvailable"),
                free_bytes: get("MemFree"),
            }),
            ..SystemFacts::default()
        },
        ..DeviceFacts::default()
    })
}
