//! Linear tokenization of `set` configuration output; secrets never enter the tree.
use crate::airos::parse::{text, ParseError};
use nm_core::{
    ConfigFormat, DeviceFacts, DhcpFacts, DhcpPool, Duplex, FirewallFacts, FirewallRule,
    FirewallRuleSet, InterfaceFacts, OffloadFacts, RedactedConfig, RoutingFacts,
};
use std::result::Result;
use std::{collections::BTreeMap, fmt::Write};

/// Ordered path to value list, suitable for deterministic serialization.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConfigTree {
    pub paths: BTreeMap<Vec<String>, Vec<String>>,
    pub secrets_removed: u32,
}
/// Secret path components whose following tokens must never be retained.
pub const SECRET_LEAVES: &[&str] = &[
    "password",
    "encrypted-password",
    "plaintext-password",
    "pre-shared-secret",
    "community",
    "secret",
    "key",
    "passphrase",
    "authentication-key",
    "md5-key",
];
/// Tokenize quotes and escaped literals without invoking a shell.
pub fn tokens(line: &str) -> Result<Vec<String>, ParseError> {
    let mut out = vec![];
    let (mut token, mut quote, mut escape, mut active) = (String::new(), None, false, false);
    for c in line.chars() {
        if escape {
            token.push(c);
            escape = false;
            active = true;
            continue;
        }
        if c == '\\' && quote != Some('\'') {
            escape = true;
            active = true;
            continue;
        }
        if let Some(q) = quote {
            if c == q {
                quote = None;
            } else {
                token.push(c);
            }
        } else if c == '\'' || c == '"' {
            quote = Some(c);
            active = true;
        } else if c.is_whitespace() {
            if active {
                out.push(std::mem::take(&mut token));
                active = false;
            }
        } else {
            token.push(c);
            active = true;
        }
    }
    if quote.is_some() || escape {
        return Err(ParseError("unterminated configuration token".into()));
    }
    if active {
        out.push(token);
    }
    Ok(out)
}
impl ConfigTree {
    /// Parse and immediately redact every secret path, including SNMP community names.
    pub fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        let mut tree = Self::default();
        for line in text(bytes)?.lines().filter(|l| !l.trim().is_empty()) {
            let mut row = tokens(line)?;
            if row.first().map(String::as_str) != Some("set") || row.len() < 3 {
                return Err(ParseError("expected set configuration commands".into()));
            }
            row.remove(0);
            if let Some(i) = row.iter().position(|v| SECRET_LEAVES.contains(&v.as_str())) {
                if row.get(i + 1).is_some_and(|v| v != "<redacted>") {
                    tree.secrets_removed += 1;
                }
                row.truncate(i + 1);
                row.push("<redacted>".into());
            }
            for token in &mut row {
                if ["$1$", "$5$", "$6$"].iter().any(|p| token.contains(p)) {
                    *token = "<redacted>".into();
                    tree.secrets_removed += 1;
                }
            }
            let value = row.pop().unwrap();
            let values = tree.paths.entry(row).or_default();
            if !values.contains(&value) {
                values.push(value);
                values.sort();
            }
        }
        if tree.paths.is_empty() {
            return Err(ParseError("empty configuration output".into()));
        }
        Ok(tree)
    }
    /// Whether any branch begins with the supplied token path.
    pub fn contains(&self, prefix: &[&str]) -> bool {
        self.paths.iter().any(|(p, v)| {
            p.iter().chain(v.iter()).zip(prefix).all(|(a, b)| a == b) && p.len() + 1 >= prefix.len()
        })
    }
    /// Serialize only the redacted tree, quoting values as shell literals.
    pub fn serialize(&self) -> String {
        let mut out = String::new();
        for (path, values) in &self.paths {
            for value in values {
                let row = path
                    .iter()
                    .chain(std::iter::once(value))
                    .map(|v| format!("'{}'", v.replace('\'', "'\\''")))
                    .collect::<Vec<_>>()
                    .join(" ");
                writeln!(out, "set {row}").unwrap();
            }
        }
        out
    }
}
/// Extract typed facts transiently, persisting only presence flags for secrets.
pub fn parse(bytes: &[u8]) -> Result<DeviceFacts, ParseError> {
    let tree = ConfigTree::parse(bytes)?;
    let mut facts = DeviceFacts::default();
    let mut rows = vec![];
    for line in text(bytes)?.lines().filter(|l| !l.trim().is_empty()) {
        let t = tokens(line)?;
        rows.push(t[1..].to_vec());
    }
    let value = |prefix: &[&str]| -> Option<String> {
        rows.iter().find_map(|r| {
            (r.len() == prefix.len() + 1 && r.iter().zip(prefix).all(|(a, b)| a == b))
                .then(|| r.last().unwrap().clone())
        })
    };
    let present = |prefix: &[&str]| tree.contains(prefix);
    facts.system.hostname = value(&["system", "host-name"]);
    facts.system.ntp_servers = rows
        .iter()
        .filter(|r| r.starts_with(&["system".into(), "ntp".into(), "server".into()]))
        .filter_map(|r| r.get(3).cloned())
        .collect();
    for (name, service) in [
        ("ssh", &mut facts.services.ssh),
        ("telnet", &mut facts.services.telnet),
        ("upnp", &mut facts.services.upnp),
    ] {
        service.enabled =
            Some(present(&["service", name]) && !present(&["service", name, "disable"]));
        service.port = value(&["service", name, "port"]).and_then(|v| v.parse().ok());
    }
    facts.services.http.enabled = Some(value(&["service", "gui", "http-port"]).is_some());
    facts.services.https.enabled =
        Some(present(&["service", "gui"]) && !present(&["service", "gui", "disable-https"]));
    facts.services.http.port = value(&["service", "gui", "http-port"]).and_then(|s| s.parse().ok());
    facts.services.https.port =
        value(&["service", "gui", "https-port"]).and_then(|s| s.parse().ok());
    let listen: Vec<_> = rows
        .iter()
        .filter(|r| r.len() == 4 && r[..3] == ["service", "gui", "listen-address"])
        .map(|r| r[3].clone())
        .collect();
    facts.services.http.listen_addresses.clone_from(&listen);
    facts.services.https.listen_addresses = listen;
    facts.services.snmp.enabled = Some(present(&["service", "snmp"]));
    facts.services.snmp.community_present = Some(present(&["service", "snmp", "community"]));
    let communities: Vec<_> = rows
        .iter()
        .filter(|r| r.len() > 3 && r[..3] == ["service", "snmp", "community"])
        .map(|r| r[3].as_str())
        .collect();
    facts.services.snmp.community_is_default = if communities.contains(&"<redacted>") {
        None
    } else {
        Some(
            communities
                .iter()
                .any(|s| matches!(*s, "public" | "private")),
        )
    };
    facts.services.discovery.enabled = Some(!present(&["service", "ubnt-discover", "disable"]));
    facts.system.netrole = Some("router".into());
    let mut ifaces: BTreeMap<String, InterfaceFacts> = BTreeMap::new();
    let mut rules: BTreeMap<String, FirewallRuleSet> = BTreeMap::new();
    for r in &rows {
        if r.len() >= 5
            && r[0] == "interfaces"
            && matches!(r[1].as_str(), "ethernet" | "pppoe" | "switch")
        {
            let f = ifaces
                .entry(r[2].clone())
                .or_insert_with(|| InterfaceFacts {
                    name: Some(r[2].clone()),
                    ..InterfaceFacts::default()
                });
            match r[3].as_str() {
                "address" => f.addresses.push(r[4].clone()),
                "description" => f.description = Some(r[4].clone()),
                "speed" => f.speed_mbps = r[4].parse().ok(),
                "duplex" => {
                    f.duplex = match r[4].as_str() {
                        "full" => Some(Duplex::Full),
                        "half" => Some(Duplex::Half),
                        _ => None,
                    }
                }
                "firewall" if r.len() == 7 && r[5] == "name" => match r[4].as_str() {
                    "in" => f.firewall_in = Some(r[6].clone()),
                    "out" => f.firewall_out = Some(r[6].clone()),
                    "local" => f.firewall_local = Some(r[6].clone()),
                    _ => {}
                },
                _ => {}
            }
        }
        if r.len() >= 5 && r[..2] == ["firewall", "name"] {
            let set = rules
                .entry(r[2].clone())
                .or_insert_with(|| FirewallRuleSet {
                    name: Some(r[2].clone()),
                    ..FirewallRuleSet::default()
                });
            if r[3] == "default-action" {
                set.default_action = Some(r[4].clone());
            }
            if r.len() >= 7 && r[3] == "rule" && r[5] == "action" {
                set.rules.push(FirewallRule {
                    number: r[4].parse().ok(),
                    action: Some(r[6].clone()),
                    ..FirewallRule::default()
                });
            }
        }
    }
    facts.interfaces = ifaces.into_values().collect();
    facts.firewall = Some(FirewallFacts {
        rule_sets: rules.into_values().collect(),
        ..FirewallFacts::default()
    });
    let routing = RoutingFacts {
        router_id: value(&["protocols", "ospf", "parameters", "router-id"]),
        ..RoutingFacts::default()
    };
    facts.routing = Some(routing);
    facts.system.offload = Some(OffloadFacts {
        ipv4_forwarding: value(&["system", "offload", "ipv4", "forwarding"]).map(|s| s == "enable"),
        ipv4_vlan: value(&["system", "offload", "ipv4", "vlan"]).map(|s| s == "enable"),
        ipv4_pppoe: value(&["system", "offload", "ipv4", "pppoe"]).map(|s| s == "enable"),
        ipv6_forwarding: value(&["system", "offload", "ipv6", "forwarding"]).map(|s| s == "enable"),
        ipv6_vlan: value(&["system", "offload", "ipv6", "vlan"]).map(|s| s == "enable"),
        ipv6_pppoe: value(&["system", "offload", "ipv6", "pppoe"]).map(|s| s == "enable"),
        ..OffloadFacts::default()
    });
    let mut pools = BTreeMap::<String, DhcpPool>::new();
    for r in &rows {
        if r.len() > 4 && r[..3] == ["service", "dhcp-server", "shared-network-name"] {
            pools.entry(r[3].clone()).or_insert_with(|| DhcpPool {
                name: Some(r[3].clone()),
                ..DhcpPool::default()
            });
        }
    }
    facts.services.dhcp_server.enabled = Some(!pools.is_empty());
    facts.dhcp = Some(DhcpFacts {
        pools: pools.into_values().collect(),
    });
    facts.config = Some(RedactedConfig {
        format: ConfigFormat::SetCommands,
        text: tree.serialize(),
        secrets_removed: tree.secrets_removed,
    });
    Ok(facts)
}
