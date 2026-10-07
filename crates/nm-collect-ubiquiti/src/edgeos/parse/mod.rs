//! Parsers for operational `EdgeOS` observations. Missing scalars remain None.
pub mod config_tree;
use crate::airos::parse::{text, ParseError};
use nm_core::{
    BgpPeer, BgpState, Confidence, DeviceFacts, DhcpFacts, DhcpPool, Duplex, FirewallFacts,
    FirewallRule, FirewallRuleSet, InterfaceCounters, InterfaceFacts, InterfaceRole, OffloadFacts,
    OspfInterface, OspfNeighbor, OspfState, RouteFacts, RoutingFacts, SystemFacts,
};
use regex::Regex;
use std::result::Result;

/// Parse `show version`, retaining the hardware model and firmware build.
pub fn version(bytes: &[u8]) -> Result<DeviceFacts, ParseError> {
    let text = text(bytes)?;
    let get = |key: &str| {
        text.lines()
            .find_map(|l| l.trim().strip_prefix(key).map(|s| s.trim().to_owned()))
    };
    let firmware = get("Version:").ok_or_else(|| ParseError("missing Version".into()))?;
    Ok(DeviceFacts {
        system: SystemFacts {
            firmware: Some(firmware),
            model: get("HW model:"),
            serial: get("HW S/N:"),
            firmware_build: get("Build ID:"),
            ..SystemFacts::default()
        },
        ..DeviceFacts::default()
    })
}
/// Parse summary interfaces, including continuation address rows.
pub fn interfaces(bytes: &[u8]) -> Result<DeviceFacts, ParseError> {
    let text = text(bytes)?;
    if !text.contains("Interface") || !text.contains("S/L") {
        return Err(ParseError("missing interface header".into()));
    }
    let mut out: Vec<InterfaceFacts> = vec![];
    for line in text.lines() {
        let c: Vec<_> = line.split_whitespace().collect();
        if c.len() >= 3 && c[2].contains('/') && c[0] != "Interface" {
            let (admin, link) = c[2].split_once('/').unwrap();
            out.push(InterfaceFacts {
                name: Some(c[0].into()),
                addresses: if c[1] == "-" {
                    vec![]
                } else {
                    vec![c[1].into()]
                },
                admin_up: Some(admin == "u"),
                oper_up: Some(link == "u"),
                description: (c.len() > 3).then(|| c[3..].join(" ")),
                ..InterfaceFacts::default()
            });
        } else if c.len() == 1 && c[0].contains('/') {
            if let Some(i) = out.last_mut() {
                i.addresses.push(c[0].into());
            }
        }
    }
    Ok(DeviceFacts {
        interfaces: out,
        ..DeviceFacts::default()
    })
}
/// Parse Linux style ethernet detail blocks, counters and negotiated speed.
pub fn if_eth_detail(bytes: &[u8]) -> Result<DeviceFacts, ParseError> {
    let text = text(bytes)?;
    let header = Regex::new(r"(?m)^((?:eth|switch|pppoe)\w+(?:\.\d+)?)\b").unwrap();
    let starts: Vec<_> = header
        .captures_iter(text)
        .map(|c| (c.get(0).unwrap().start(), c[1].to_owned()))
        .collect();
    if starts.is_empty() {
        return Err(ParseError("no ethernet detail blocks".into()));
    }
    let speed = Regex::new(r"(?i)(\d+)\s*(?:Mb/s|Mbps)").unwrap();
    let mac = Regex::new(r"(?i)\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b").unwrap();
    let mut out = vec![];
    for (i, (start, name)) in starts.iter().enumerate() {
        let block = &text[*start..starts.get(i + 1).map_or(text.len(), |(n, _)| *n)];
        let low = block.to_ascii_lowercase();
        let mut counters = InterfaceCounters::default();
        for line in block.lines() {
            let l = line.to_ascii_lowercase();
            let get = |key: &str| {
                Regex::new(&format!(r"{key}[:\s]+(\d+)"))
                    .unwrap()
                    .captures(&l)
                    .and_then(|c| c[1].parse().ok())
            };
            if l.contains("rx") {
                counters.rx_packets = get("packets").or(counters.rx_packets);
                counters.rx_bytes = get("bytes").or(counters.rx_bytes);
                counters.rx_errors = get("errors").or(counters.rx_errors);
                counters.rx_dropped = get("dropped").or(counters.rx_dropped);
            }
            if l.contains("tx") {
                counters.tx_packets = get("packets").or(counters.tx_packets);
                counters.tx_bytes = get("bytes").or(counters.tx_bytes);
                counters.tx_errors = get("errors").or(counters.tx_errors);
                counters.tx_dropped = get("dropped").or(counters.tx_dropped);
            }
        }
        out.push(InterfaceFacts {
            name: Some(name.clone()),
            mac: mac.find(block).map(|m| m.as_str().to_ascii_lowercase()),
            speed_mbps: speed.captures(block).and_then(|c| c[1].parse().ok()),
            duplex: if low.contains("half") {
                Some(Duplex::Half)
            } else if low.contains("full") {
                Some(Duplex::Full)
            } else {
                None
            },
            counters: Some(counters),
            ..InterfaceFacts::default()
        });
    }
    Ok(DeviceFacts {
        interfaces: out,
        ..DeviceFacts::default()
    })
}
/// Parse route protocol counts from the summary table.
pub fn route_summary(bytes: &[u8]) -> Result<DeviceFacts, ParseError> {
    let text = text(bytes)?;
    let mut r = RoutingFacts::default();
    for line in text.lines() {
        let c: Vec<_> = line.split_whitespace().collect();
        if c.len() >= 2 {
            if let Ok(n) = c[1].parse() {
                r.protocol_counts.insert(c[0].to_ascii_lowercase(), n);
            }
        }
    }
    if r.protocol_counts.is_empty() {
        return Err(ParseError("no route summary counts".into()));
    }
    Ok(DeviceFacts {
        routing: Some(r),
        ..DeviceFacts::default()
    })
}
/// Parse routes and ECMP continuations from the operational routing table.
pub fn route(bytes: &[u8]) -> Result<DeviceFacts, ParseError> {
    let text = text(bytes)?;
    let mut r = RoutingFacts::default();
    let mut previous: Option<RouteFacts> = None;
    let metric = Regex::new(r"\[\d+/(\d+)\]").unwrap();
    for line in text.lines() {
        let c: Vec<_> = line.split_whitespace().collect();
        let prefix = c.iter().position(|s| {
            s.contains('/')
                && s.split('/')
                    .next()
                    .is_some_and(|p| p.parse::<std::net::IpAddr>().is_ok())
        });
        let mut row = if let Some(i) = prefix {
            RouteFacts {
                prefix: Some(c[i].into()),
                protocol: c.first().map(|s| s.trim_matches(['>', '*']).to_owned()),
                ..RouteFacts::default()
            }
        } else if line.trim().starts_with("via") || line.trim().starts_with('*') {
            let Some(p) = previous.clone() else {
                continue;
            };
            p
        } else {
            continue;
        };
        row.metric = metric
            .captures(line)
            .and_then(|c| c[1].parse().ok())
            .or(row.metric);
        if let Some(i) = c.iter().position(|s| *s == "via") {
            row.next_hop = c.get(i + 1).map(|s| s.trim_end_matches(',').into());
            row.interface = c
                .get(i + 2)
                .filter(|s| !s.contains(':'))
                .map(|s| s.trim_end_matches(',').into());
        } else if let Some(i) = c.iter().position(|s| *s == "connected,") {
            row.interface = c.get(i + 1).map(|s| s.trim_end_matches(',').into());
        }
        previous = Some(row.clone());
        r.routes.push(row);
    }
    if r.routes.is_empty() && !text.contains("Codes:") {
        return Err(ParseError("no routing table".into()));
    }
    Ok(DeviceFacts {
        routing: Some(r),
        ..DeviceFacts::default()
    })
}
/// Parse OSPF adjacency state, preserving non-Full states as observed.
pub fn ospf_neighbor(bytes: &[u8]) -> Result<DeviceFacts, ParseError> {
    let text = text(bytes)?;
    let mut r = RoutingFacts::default();
    if !text.contains("Neighbor ID") {
        return Err(ParseError("missing OSPF header".into()));
    }
    for line in text.lines() {
        let c: Vec<_> = line.split_whitespace().collect();
        if c.len() < 6 || c[0].parse::<std::net::Ipv4Addr>().is_err() {
            continue;
        }
        let state = match c[2].split('/').next().unwrap() {
            "Full" => Some(OspfState::Full),
            "2-Way" => Some(OspfState::TwoWay),
            "ExStart" => Some(OspfState::ExStart),
            "Init" => Some(OspfState::Init),
            "Exchange" => Some(OspfState::Exchange),
            "Loading" => Some(OspfState::Loading),
            "Down" => Some(OspfState::Down),
            "Attempt" => Some(OspfState::Attempt),
            _ => None,
        };
        r.ospf_neighbors.push(OspfNeighbor {
            router_id: Some(c[0].into()),
            state,
            address: Some(c[4].into()),
            interface: Some(c[5].split(':').next().unwrap().into()),
        });
    }
    Ok(DeviceFacts {
        routing: Some(r),
        ..DeviceFacts::default()
    })
}
/// Parse OSPF interface blocks with area, cost, designated routers and timers.
pub fn ospf_interface(bytes: &[u8]) -> Result<DeviceFacts, ParseError> {
    let text = text(bytes)?;
    let mut r = RoutingFacts::default();
    let header = Regex::new(r"(?m)^(\S+) is (?:up|down)").unwrap();
    let blocks: Vec<_> = header
        .captures_iter(text)
        .map(|c| (c.get(0).unwrap().start(), c[1].to_owned()))
        .collect();
    if blocks.is_empty() && !text.trim().is_empty() {
        return Err(ParseError("no OSPF interfaces".into()));
    }
    for (i, (start, name)) in blocks.iter().enumerate() {
        let block = &text[*start..blocks.get(i + 1).map_or(text.len(), |(n, _)| *n)];
        let get = |pattern: &str| {
            Regex::new(pattern)
                .unwrap()
                .captures(block)
                .map(|c| c[1].to_owned())
        };
        r.ospf_interfaces.push(OspfInterface {
            name: Some(name.clone()),
            area: get(r"Area\s+(\S+)").map(|s| s.trim_end_matches(',').into()),
            cost: get(r"Cost:\s*(\d+)").and_then(|s| s.parse().ok()),
            state: get(r"State\s+(\w+)"),
            dr: get(r"Designated Router \(ID\)\s+(\S+)"),
            bdr: get(r"Backup Designated Router \(ID\)\s+(\S+)"),
            hello_seconds: get(r"Hello\s+(\d+)").and_then(|s| s.parse().ok()),
            dead_seconds: get(r"Dead\s+(\d+)").and_then(|s| s.parse().ok()),
        });
    }
    Ok(DeviceFacts {
        routing: Some(r),
        ..DeviceFacts::default()
    })
}
/// Numeric BGP state column is an Established session with a prefix count.
pub fn bgp_summary(bytes: &[u8]) -> Result<DeviceFacts, ParseError> {
    let text = text(bytes)?;
    if !text.contains("State/PfxRcd") {
        return Err(ParseError("missing BGP header".into()));
    }
    let mut r = RoutingFacts::default();
    for line in text.lines() {
        let c: Vec<_> = line.split_whitespace().collect();
        if c.len() < 10 || c[0].parse::<std::net::IpAddr>().is_err() {
            continue;
        }
        let v = &c[9];
        let prefixes = v.parse().ok();
        let state = if prefixes.is_some() {
            Some(BgpState::Established)
        } else {
            match *v {
                "Idle" => Some(BgpState::Idle),
                "Connect" => Some(BgpState::Connect),
                "Active" => Some(BgpState::Active),
                "OpenSent" => Some(BgpState::OpenSent),
                "OpenConfirm" => Some(BgpState::OpenConfirm),
                _ => None,
            }
        };
        r.bgp_peers.push(BgpPeer {
            address: Some(c[0].into()),
            remote_as: c[2].parse().ok(),
            state,
            prefixes_received: prefixes,
        });
    }
    Ok(DeviceFacts {
        routing: Some(r),
        ..DeviceFacts::default()
    })
}
/// Parse both Cavium and `MediaTek` offload output without inventing missing flags.
pub fn offload(bytes: &[u8]) -> Result<DeviceFacts, ParseError> {
    let text = text(bytes)?;
    let mut f = OffloadFacts::default();
    let mut family = "";
    for line in text.lines() {
        let low = line.trim().to_ascii_lowercase();
        if low.starts_with("ipv4") {
            family = "ipv4";
        }
        if low.starts_with("ipv6") {
            family = "ipv6";
        }
        let enabled = if low.contains("disabled") || low.contains("not loaded") {
            Some(false)
        } else if low.contains("enabled") || low.contains("is loaded") {
            Some(true)
        } else {
            None
        };
        if enabled.is_none() {
            continue;
        }
        if low.contains("hwnat") {
            f.ipv4_forwarding = enabled;
        }
        if low.contains("ipsec") {
            f.ipsec = enabled;
        }
        if low.contains("forwarding") {
            if family == "ipv6" {
                f.ipv6_forwarding = enabled;
            } else {
                f.ipv4_forwarding = enabled;
            }
        }
        if low.contains("vlan") {
            if family == "ipv6" {
                f.ipv6_vlan = enabled;
            } else {
                f.ipv4_vlan = enabled;
            }
        }
        if low.contains("pppoe") {
            if family == "ipv6" {
                f.ipv6_pppoe = enabled;
            } else {
                f.ipv4_pppoe = enabled;
            }
        }
    }
    if f == OffloadFacts::default() {
        return Err(ParseError("no offload observations".into()));
    }
    Ok(DeviceFacts {
        system: SystemFacts {
            offload: Some(f),
            ..SystemFacts::default()
        },
        ..DeviceFacts::default()
    })
}
/// Parse pool size, leased and available columns from DHCP statistics.
pub fn dhcp_stats(bytes: &[u8]) -> Result<DeviceFacts, ParseError> {
    let text = text(bytes)?;
    if !text.to_ascii_lowercase().contains("pool") {
        return Err(ParseError("missing DHCP pools header".into()));
    }
    let mut pools = vec![];
    for line in text.lines() {
        let c: Vec<_> = line.split_whitespace().collect();
        if c.len() >= 4 {
            if let (Ok(size), Ok(leased), Ok(available)) =
                (c[1].parse(), c[2].parse(), c[3].parse())
            {
                pools.push(DhcpPool {
                    name: Some(c[0].into()),
                    size: Some(size),
                    leased: Some(leased),
                    available: Some(available),
                });
            }
        }
    }
    Ok(DeviceFacts {
        dhcp: Some(DhcpFacts { pools }),
        ..DeviceFacts::default()
    })
}
/// Count leases by pool; statistics later supply authoritative capacity totals.
pub fn dhcp_leases(bytes: &[u8]) -> Result<DeviceFacts, ParseError> {
    let text = text(bytes)?;
    if !text.contains("IP address") && !text.contains("IP Address") {
        return Err(ParseError("missing DHCP lease header".into()));
    }
    let mut pools = std::collections::BTreeMap::<String, u32>::new();
    for line in text.lines() {
        let c: Vec<_> = line.split_whitespace().collect();
        if c.first()
            .is_some_and(|s| s.parse::<std::net::IpAddr>().is_ok())
            && c.len() >= 5
        {
            *pools.entry(c[4].to_string()).or_default() += 1;
        }
    }
    Ok(DeviceFacts {
        dhcp: Some(DhcpFacts {
            pools: pools
                .into_iter()
                .map(|(name, n)| DhcpPool {
                    name: Some(name),
                    leased: Some(n),
                    ..DhcpPool::default()
                })
                .collect(),
        }),
        ..DeviceFacts::default()
    })
}
/// Parse per-rule packet and byte counters from firewall or NAT tables.
pub fn firewall_stats(bytes: &[u8], nat: bool) -> Result<DeviceFacts, ParseError> {
    let text = text(bytes)?;
    let mut firewall = FirewallFacts::default();
    let mut current = FirewallRuleSet::default();
    for line in text.lines() {
        let c: Vec<_> = line.split_whitespace().collect();
        if let Some(rest) = line
            .trim()
            .strip_prefix("IPv4 Firewall ")
            .or_else(|| line.trim().strip_prefix("Firewall "))
        {
            if current.name.is_some() {
                firewall.rule_sets.push(std::mem::take(&mut current));
            }
            current.name = Some(rest.trim_end_matches(':').into());
        }
        if c.len() >= 3 {
            if let (Ok(number), Ok(packets), Ok(bytes)) = (c[0].parse(), c[1].parse(), c[2].parse())
            {
                let rule = FirewallRule {
                    number: Some(number),
                    packets: Some(packets),
                    bytes: Some(bytes),
                    action: c.get(3).map(|s| (*s).into()),
                };
                if nat {
                    firewall.nat_rules.push(rule);
                } else {
                    current.rules.push(rule);
                }
            }
        }
    }
    if current.name.is_some() || !current.rules.is_empty() {
        firewall.rule_sets.push(current);
    }
    if firewall.rule_sets.is_empty()
        && firewall.nat_rules.is_empty()
        && !text.to_lowercase().contains("rule")
    {
        return Err(ParseError("no firewall statistics".into()));
    }
    Ok(DeviceFacts {
        firewall: Some(firewall),
        ..DeviceFacts::default()
    })
}
/// Infer WAN interfaces only from observed routes, explicit descriptions or public dynamic IPs.
pub fn infer_wan(facts: &mut DeviceFacts) {
    let defaults: Vec<_> = facts
        .routing
        .as_ref()
        .map(|r| {
            r.routes
                .iter()
                .filter(|r| matches!(r.prefix.as_deref(), Some("0.0.0.0/0" | "::/0")))
                .filter_map(|r| r.interface.clone())
                .collect()
        })
        .unwrap_or_default();
    for i in &mut facts.interfaces {
        let route = i.name.as_ref().is_some_and(|n| defaults.contains(n));
        let described = i.description.as_ref().is_some_and(|s| {
            ["wan", "internet", "upstream", "uplink"]
                .iter()
                .any(|p| s.to_ascii_lowercase().contains(p))
        });
        let dynamic = i.name.as_ref().is_some_and(|n| n.starts_with("pppoe"))
            || i.addresses.iter().any(|a| a == "dhcp");
        let public = i
            .addresses
            .iter()
            .filter_map(|a| a.split('/').next()?.parse::<std::net::IpAddr>().ok())
            .any(|a| match a {
                std::net::IpAddr::V4(a) => {
                    !(a.is_private()
                        || a.is_link_local()
                        || a.is_loopback()
                        || a.is_unspecified()
                        || a.is_multicast()
                        || a.is_broadcast()
                        || (a.octets()[0] == 100 && (64..128).contains(&a.octets()[1])))
                }
                std::net::IpAddr::V6(a) => {
                    !a.is_unique_local()
                        && !a.is_unicast_link_local()
                        && !a.is_loopback()
                        && !a.is_unspecified()
                }
            });
        if route || described || (dynamic && public) {
            i.role = Some(InterfaceRole::Wan);
            i.role_confidence = Some(if route {
                Confidence::Likely
            } else {
                Confidence::Heuristic
            });
        }
    }
}
