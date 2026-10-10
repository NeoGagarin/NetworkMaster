//! Secret removal for raw device output before it is persisted (SPEC §1.3 N3).
//!
//! Redaction is by key shape, not by a list of known key spellings. A real
//! `LiteBeam` on airOS 8.7.22 carried its WPA pre-shared key under
//! `aaa.1.wpa.psk` and `wpasupplicant.profile.1.network.1.psk`, neither of
//! which the original spelling list covered. Any dotted key with a secret
//! segment is redacted; the key stays so presence can still be reasoned about.
use nm_core::DeviceFamily;
use regex::{Captures, Regex};
use std::{collections::BTreeMap, sync::LazyLock};

/// Dotted-key segments whose value is a secret wherever they appear.
const SECRET_SEGMENTS: &[&str] = &[
    "password",
    "passwd",
    "passphrase",
    "psk",
    "secret",
    "community",
    "key",
    "token",
    "wpa_psk",
    "private",
];
/// Whole keys whose value embeds a credential (URIs with device tokens).
const SECRET_KEYS: &[&str] = &["unms.uri", "unms.token"];

// The value excludes the carriage return so CRLF input scrubs identically.
static KEY_VALUE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^([A-Za-z0-9_.\-]+)=([^\r\n]*)").unwrap());
static CRYPT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\$(?:1|5|6|2[aby]?)\$(?:rounds=\d+\$)?[./A-Za-z0-9]+\$?[./A-Za-z0-9]*").unwrap()
});
static JSON_SECRET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)("(?:[a-z0-9_]*(?:password|passwd|passphrase|psk|secret|community|token)[a-z0-9_]*)"\s*:\s*)"(?:\\.|[^"\\])*""#,
    )
    .unwrap()
});

fn key_is_secret(key: &str) -> bool {
    if SECRET_KEYS.contains(&key) {
        return true;
    }
    key.split('.').any(|segment| {
        let segment = segment.to_ascii_lowercase();
        SECRET_SEGMENTS.contains(&segment.as_str())
    })
}

pub fn scrub_secrets(_family: DeviceFamily, _artifact_name: &str, bytes: &[u8]) -> (Vec<u8>, u32) {
    let text = String::from_utf8_lossy(bytes);
    let mut removed = 0;
    let text = KEY_VALUE.replace_all(&text, |c: &Captures<'_>| {
        if key_is_secret(&c[1]) && !c[2].is_empty() && &c[2] != "<redacted>" {
            removed += 1;
            format!("{}=<redacted>", &c[1])
        } else {
            c[0].to_string()
        }
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
static BARE_MAC: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?im)^(board\.hwaddr=)([0-9a-f]{12})$").unwrap());
static BRIDGE_MAC: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b([0-9a-f]{4})\.([0-9a-f]{12})\b").unwrap());
static NAME: LazyLock<Regex> = LazyLock::new(|| {
    // Key forms are anchored to line start or a comma so `hide_ssid=disabled`
    // is not mistaken for an SSID.
    Regex::new(r#"(?mi)("(?:hostname|deviceName|name|essid|ssid)"\s*:\s*")([^"
]*)(")|(^|,)((?:deviceName|hostname|ssid|essid|wireless\.\d+\.ssid|wpasupplicant\.profile\.\d+\.network\.\d+\.ssid|resolv\.host\.\d+\.name)=)([^,
]*)"#).unwrap()
});
static DEVICE_ID: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^(board\.device_id=)[0-9a-f]+$").unwrap());
impl FixtureTokenizer {
    fn mac_token(&mut self, mac: String) -> String {
        let n = self.macs.len() + 1;
        self.macs
            .entry(mac)
            .or_insert_with(|| {
                format!(
                    "02:00:00:{:02x}:{:02x}:{:02x}",
                    (n >> 16) & 255,
                    (n >> 8) & 255,
                    n & 255
                )
            })
            .clone()
    }
    pub fn tokenize(&mut self, bytes: &[u8]) -> Vec<u8> {
        let text = String::from_utf8_lossy(bytes);
        let text = MAC.replace_all(&text, |c: &Captures<'_>| {
            self.mac_token(c[0].to_ascii_lowercase().replace('-', ":"))
        });
        let text = BARE_MAC.replace_all(&text, |c: &Captures<'_>| {
            let mac = c[2]
                .as_bytes()
                .chunks(2)
                .map(|pair| {
                    std::str::from_utf8(pair)
                        .unwrap_or("00")
                        .to_ascii_lowercase()
                })
                .collect::<Vec<_>>()
                .join(":");
            format!(
                "{}{}",
                &c[1],
                self.mac_token(mac).replace(':', "").to_ascii_uppercase()
            )
        });
        let text = BRIDGE_MAC.replace_all(&text, |c: &Captures<'_>| {
            let mac = c[2]
                .as_bytes()
                .chunks(2)
                .map(|pair| {
                    std::str::from_utf8(pair)
                        .unwrap_or("00")
                        .to_ascii_lowercase()
                })
                .collect::<Vec<_>>()
                .join(":");
            let token = self.mac_token(mac);
            format!("{}.{}", &c[1], token.replace(':', ""))
        });
        let text = IP.replace_all(&text, |c: &Captures<'_>| {
            let Ok(ip) = c[0].parse::<std::net::Ipv4Addr>() else {
                return c[0].to_string();
            };
            // Netmasks, wildcards and broadcast addresses carry no identity.
            if ip.is_unspecified() || ip.is_broadcast() || ip.is_loopback() || is_netmask(ip) {
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
            let (lead, prefix, value, suffix) = if let Some(prefix) = c.get(1) {
                ("", prefix.as_str(), &c[2], "\"")
            } else {
                (&c[4], &c[5], &c[6], "")
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
            format!("{lead}{prefix}{token}{suffix}")
        });
        let text = DEVICE_ID.replace_all(&text, |c: &Captures<'_>| {
            format!("{}{}", &c[1], "0".repeat(32))
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
fn is_netmask(ip: std::net::Ipv4Addr) -> bool {
    let bits = u32::from(ip);
    bits != 0 && (!bits).wrapping_add(1) & !bits == 0
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
        let text = "users.1.password=hunter2\nsnmp.community=public\nwireless.1.wpa.psk=hunter2\nwireless.1.wep.key.1=hunter2\nwireless.1.wpa.1x.radius.password=hunter2\nntpclient.1.password=hunter2\narbitrary=$6$salt$abcdef\nusers.1.name=operator\n{\"password\":\"hunter2\"}";
        let (bytes, count) = scrub_secrets(DeviceFamily::AirOs, "any.txt", text.as_bytes());
        let text = String::from_utf8(bytes).unwrap();
        assert_eq!(count, 8);
        assert!(!text.contains("hunter2"));
        assert!(!text.contains("$6$"));
        assert!(text.contains("users.1.name=operator"));
        assert!(text.contains("snmp.community=<redacted>"));
    }
    #[test]
    fn scrubs_the_spellings_a_real_airos_8_radio_uses() {
        // Observed on a `LiteBeam 5AC Gen2`, airOS 8.7.22, during hardware validation.
        let text = "aaa.1.wpa.psk=linkkey\nwpasupplicant.profile.1.network.1.psk=linkkey\nwpasupplicant.profile.1.network.1.key_mgmt.1.name=WPA-PSK\naaa.1.radius.auth.1.secret=rad\nunms.uri=wss://172.16.2.8:443+95LpUhKBz3UlS8+allowUntrustedCertificate\nunms.ui_url=https://172.16.2.8\npwdog.status=disabled\nsystem.cfg.editor.tshaper=5b854359-2b87fbbb483e8f03d30674a5df844750\nwireless.1.security.type=none\n";
        let (bytes, count) = scrub_secrets(DeviceFamily::AirOs, "system.cfg", text.as_bytes());
        let text = String::from_utf8(bytes).unwrap();
        assert!(!text.contains("linkkey"), "{text}");
        assert!(!text.contains("rad\n"), "{text}");
        assert!(!text.contains("95LpUhKBz3UlS8"), "{text}");
        assert!(
            text.contains("key_mgmt.1.name=WPA-PSK"),
            "key_mgmt is a name, not a key"
        );
        assert!(
            text.contains("unms.ui_url=https://172.16.2.8"),
            "the UI URL has no credential"
        );
        assert!(
            text.contains("pwdog.status=disabled"),
            "pwdog is a watchdog, not a password"
        );
        assert!(text.contains("wireless.1.security.type=none"));
        assert_eq!(count, 4);
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
    #[test]
    fn tokenizer_keeps_masks_and_rewrites_board_identity() {
        let mut t = FixtureTokenizer::default();
        let out = String::from_utf8(t.tokenize(
            b"netmask=255.255.255.0\nwlanIpAddress=0.0.0.0\nboard.hwaddr=28704EBEE5B6\nboard.device_id=cd5d389eef2435480562498672b3f177\ndeviceId=28:70:4E:BE:E5:B6\n",
        ))
        .unwrap();
        assert!(out.contains("netmask=255.255.255.0"));
        assert!(out.contains("wlanIpAddress=0.0.0.0"));
        assert!(out.contains("board.hwaddr=020000000001"));
        assert!(out.contains("deviceId=02:00:00:00:00:01"), "{out}");
        assert!(out.contains(&format!("board.device_id={}", "0".repeat(32))));
        let cfg = String::from_utf8(t.tokenize(
            b"wireless.1.hide_ssid=disabled
wireless.1.ssid=Customers
",
        ))
        .unwrap();
        assert!(cfg.contains("wireless.1.hide_ssid=disabled"), "{cfg}");
        assert!(cfg.contains("wireless.1.ssid=fixture-ssid-"), "{cfg}");
    }
}
