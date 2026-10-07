use nm_core::DeviceFamily;
use regex::{Captures, Regex};
use std::{collections::BTreeMap, sync::LazyLock};

static SECRET_LINE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?mi)^(users\.\d+\.password|snmp\.community|wireless\.\d+\.(?:wpa\.psk|wep\.key\.\d+|wpa\.1x\..*password)|pwd\.?[^=]*|ntpclient\..*\.password)=.*$").unwrap()
});
static CRYPT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\$(?:1|5|6)\$(?:rounds=\d+\$)?[./A-Za-z0-9]+\$[./A-Za-z0-9]+").unwrap()
});
static JSON_SECRET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)("(?:password|passwd|community|psk|wpa_psk|secret|token)"\s*:\s*)"(?:\\.|[^"\\])*""#,
    )
    .unwrap()
});

pub fn scrub_secrets(_family: DeviceFamily, _artifact_name: &str, bytes: &[u8]) -> (Vec<u8>, u32) {
    let text = String::from_utf8_lossy(bytes);
    let mut removed = 0;
    let text = SECRET_LINE.replace_all(&text, |c: &Captures<'_>| {
        removed += 1;
        format!("{}=<redacted>", &c[1])
    });
    let text = CRYPT.replace_all(&text, |_: &Captures<'_>| {
        removed += 1;
        "<redacted>"
    });
    let text = JSON_SECRET.replace_all(&text, |c: &Captures<'_>| {
        removed += 1;
        format!("{}\"<redacted>\"", &c[1])
    });
    (text.as_bytes().to_vec(), removed)
}

/// One tokenizer is shared across every artifact in a capture, preserving relationships.
#[derive(Default)]
pub struct FixtureTokenizer {
    ips: BTreeMap<String, String>,
    macs: BTreeMap<String, String>,
    names: BTreeMap<String, String>,
    ssids: BTreeMap<String, String>,
    ipv6: BTreeMap<String, String>,
}
static IP: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap());
static MAC: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b[0-9a-f]{2}(?:[:-][0-9a-f]{2}){5}\b").unwrap());
static BRIDGE_MAC: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b([0-9a-f]{4})\.([0-9a-f]{12})\b").unwrap());
static NAME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?mi)("(?:hostname|deviceName|name|essid|ssid)"\s*:\s*")([^"\r\n]*)(")|((?:deviceName|hostname|ssid|wireless\.\d+\.ssid|resolv\.host\.\d+\.name)=)([^,\r\n]*)"#).unwrap()
});
impl FixtureTokenizer {
    pub fn tokenize(&mut self, bytes: &[u8]) -> Vec<u8> {
        let text = String::from_utf8_lossy(bytes);
        let text = MAC.replace_all(&text, |c: &Captures<'_>| {
            let n = self.macs.len() + 1;
            self.macs
                .entry(c[0].to_ascii_lowercase().replace('-', ":"))
                .or_insert_with(|| {
                    format!(
                        "02:00:00:{:02x}:{:02x}:{:02x}",
                        (n >> 16) & 255,
                        (n >> 8) & 255,
                        n & 255
                    )
                })
                .clone()
        });
        let text = BRIDGE_MAC.replace_all(&text, |c: &Captures<'_>| {
            let mac = c[2]
                .as_bytes()
                .chunks(2)
                .map(|pair| std::str::from_utf8(pair).unwrap().to_ascii_lowercase())
                .collect::<Vec<_>>()
                .join(":");
            let n = self.macs.len() + 1;
            let token = self.macs.entry(mac).or_insert_with(|| {
                format!(
                    "02:00:00:{:02x}:{:02x}:{:02x}",
                    (n >> 16) & 255,
                    (n >> 8) & 255,
                    n & 255
                )
            });
            format!("{}.{}", &c[1], token.replace(':', ""))
        });
        let text = IP.replace_all(&text, |c: &Captures<'_>| {
            if c[0].parse::<std::net::Ipv4Addr>().is_err() {
                return c[0].to_string();
            }
            let n = self.ips.len() + 1;
            self.ips
                .entry(c[0].into())
                .or_insert_with(|| {
                    if n <= 254 {
                        format!("192.0.2.{n}")
                    } else {
                        format!("198.51.100.{}", (n - 255) % 254 + 1)
                    }
                })
                .clone()
        });
        let text = IPV6.replace_all(&text, |c: &Captures<'_>| {
            let Ok(ip) = c[0].parse::<std::net::Ipv6Addr>() else {
                return c[0].into();
            };
            let n = self.ipv6.len() + 1;
            self.ipv6
                .entry(ip.to_string())
                .or_insert_with(|| format!("2001:db8::{n:x}"))
                .clone()
        });
        let text = ESSID.replace_all(&text, |c: &Captures<'_>| {
            let n = self.ssids.len() + 1;
            let token = self
                .ssids
                .entry(c[1].into())
                .or_insert_with(|| format!("fixture-ssid-{n}"));
            format!("ESSID:\"{token}\"")
        });
        let text = NAME.replace_all(&text, |c: &Captures<'_>| {
            let (prefix, value, suffix) = if let Some(prefix) = c.get(1) {
                (prefix.as_str(), &c[2], "\"")
            } else {
                (&c[4], &c[5], "")
            };
            let ssid = prefix.to_ascii_lowercase().contains("ssid");
            let map = if ssid {
                &mut self.ssids
            } else {
                &mut self.names
            };
            let n = map.len() + 1;
            let token = map
                .entry(value.into())
                .or_insert_with(|| format!("fixture-{}-{n}", if ssid { "ssid" } else { "host" }));
            format!("{prefix}{token}{suffix}")
        });
        let text = EDGE_ID.replace_all(&text, |c: &Captures<'_>| {
            let n = self.names.len() + 1;
            let token = self
                .names
                .entry(c[2].into())
                .or_insert_with(|| format!("fixture-identity-{n}"));
            format!("{}{}", &c[1], token)
        });
        text.as_bytes().to_vec()
    }
}
static EDGE_ID: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^(HW S/N:\s*|set (?:'system' 'host-name'|system host-name)\s+)([^\r\n]+)$")
        .unwrap()
});
static ESSID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"ESSID:"([^"\r\n]*)""#).unwrap());
static IPV6: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}").unwrap());
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scrubs_every_pattern_and_hashes_in_arbitrary_artifacts() {
        let text = "users.1.password=hunter2\nsnmp.community=public\nwireless.1.wpa.psk=hunter2\nwireless.1.wep.key.1=hunter2\nwireless.1.wpa.1x.radius.password=hunter2\npwd.1=hunter2\npwd=hunter2\nntpclient.1.password=hunter2\narbitrary=$6$salt$abcdef\nusers.1.name=operator\n{\"password\":\"hunter2\"}";
        let (bytes, count) = scrub_secrets(DeviceFamily::AirOs, "any.txt", text.as_bytes());
        let text = String::from_utf8(bytes).unwrap();
        assert_eq!(count, 10);
        assert!(!text.contains("hunter2"));
        assert!(!text.contains("$6$"));
        assert!(text.contains("users.1.name=operator"));
    }
    #[test]
    fn tokens_are_consistent_and_remove_private_identifiers() {
        let mut t = FixtureTokenizer::default();
        let a = t.tokenize(b"hostname=tower\nssid=Customers\n10.1.2.3 aa:bb:cc:dd:ee:ff");
        assert_eq!(
            a,
            t.tokenize(b"hostname=tower\nssid=Customers\n10.1.2.3 aa:bb:cc:dd:ee:ff")
        );
        let a = String::from_utf8(a).unwrap();
        assert!(a.contains("192.0.2.1 02:00:00:00:00:01"));
        assert!(!a.contains("Customers"));
        let bridge = String::from_utf8(t.tokenize(b"8000.AABBCCDDEEFF")).unwrap();
        assert_eq!(bridge, "8000.020000000001");
        let ipv6 = String::from_utf8(t.tokenize(b"fd12:3456::1 ESSID:\"Customers\"")).unwrap();
        assert_eq!(ipv6, "2001:db8::1 ESSID:\"fixture-ssid-1\"");
    }
}
