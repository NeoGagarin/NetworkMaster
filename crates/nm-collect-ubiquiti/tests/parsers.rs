use nm_collect_ubiquiti::airos::{collector::parse_artifacts, parse};
use nm_core::*;
use sha2::{Digest, Sha256};

fn fixture_root(fixture: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/airos")
        .join(fixture)
}

/// Artifacts a fixture's `meta.toml` lists as missing on that firmware.
fn missing_commands(root: &std::path::Path) -> Vec<String> {
    let meta = std::fs::read_to_string(root.join("meta.toml")).unwrap_or_default();
    let table: toml::Table = meta.parse().unwrap_or_default();
    table
        .get("missing")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn raw_artifacts(root: &std::path::Path) -> Vec<RawArtifact> {
    let mut raw: Vec<_> = std::fs::read_dir(root)
        .unwrap()
        .filter_map(|e| {
            let p = e.unwrap().path();
            let name = p.file_name()?.to_str()?.to_owned();
            if name == "meta.toml" {
                return None;
            }
            let bytes = std::fs::read(p).unwrap();
            Some(RawArtifact {
                kind: ArtifactKind::Text,
                name,
                sha256: Sha256::digest(&bytes).into(),
                bytes,
                redacted: true,
            })
        })
        .collect();
    raw.sort_by(|a, b| a.name.cmp(&b.name));
    raw
}

/// Golden parser output for every fixture: two synthetic shapes and one real
/// `LiteBeam 5AC Gen2` capture on airOS 8.7.22. Artifacts the fixture marks as
/// missing are skipped, as the collector would skip them.
#[test]
fn parser_goldens_for_every_fixture() {
    for fixture in [
        "synthetic-xw-6.3.6",
        "synthetic-wa-8.7.11",
        "lbe-5ac-gen2-wa-8.7.22",
    ] {
        let root = fixture_root(fixture);
        let missing = missing_commands(&root);
        let read = |f: &str| std::fs::read(root.join(f)).unwrap();
        macro_rules! golden {
            ($name:literal, $command:literal, $value:expr) => {
                if !missing.iter().any(|m| m == $command) {
                    insta::assert_json_snapshot!(
                        format!("{fixture}_{}", $name),
                        $value.expect(concat!($name, " must parse"))
                    );
                }
            };
        }
        golden!(
            "version",
            "cat /etc/version",
            parse::version::parse(&read("version.txt"))
        );
        golden!(
            "board",
            "cat /etc/board.info",
            parse::board_info::parse(&read("board-info.txt"))
        );
        golden!(
            "status",
            "mca-status",
            parse::mca_status::parse(&read("mca-status.txt"))
        );
        golden!(
            "dump",
            "mca-dump",
            parse::mca_dump::parse(&read("mca-dump.json"))
        );
        if root.join("wstalist.json").exists() {
            golden!(
                "stations",
                "wstalist",
                parse::wstalist::parse(&read("wstalist.json"))
            );
        }
        golden!(
            "config",
            "cat /tmp/system.cfg",
            parse::system_cfg::parse(&read("system.cfg"))
        );
        golden!(
            "iwconfig",
            "iwconfig",
            parse::iwconfig::parse(&read("iwconfig.txt"))
        );
        golden!(
            "ifconfig",
            "ifconfig",
            parse::ifconfig::parse(&read("ifconfig.txt"))
        );
        golden!(
            "counters",
            "cat /proc/net/dev",
            parse::proc_net_dev::parse(&read("proc-net-dev.txt"))
        );
        golden!(
            "arp",
            "cat /proc/net/arp",
            parse::arp::parse(&read("arp.txt"))
        );
        golden!(
            "uptime",
            "uptime",
            parse::system::uptime(&read("uptime.txt"))
        );
        golden!("free", "free", parse::system::free(&read("free.txt")));
        golden!(
            "loadavg",
            "cat /proc/loadavg",
            parse::system::loadavg(&read("loadavg.txt"))
        );
        let mut coverage = Coverage {
            missing: missing.clone(),
            ..Coverage::default()
        };
        let facts = parse_artifacts(&raw_artifacts(&root), &mut coverage);
        insta::assert_json_snapshot!(format!("{fixture}_merged"), facts);
        let radio = facts.radio.clone().expect("radio facts");
        assert!(
            radio.channel_width_mhz.is_some(),
            "{fixture}: channel width"
        );
        assert!(
            facts.interfaces.iter().any(|i| i.mac.is_some()),
            "{fixture}: interface MAC"
        );
        let config = facts.config.expect("config");
        assert!(!config.text.contains("hunter2"));
        // Fixtures are committed already redacted, so the parse-time count can
        // be zero; what matters is that every secret key carries the marker.
        assert!(
            config.text.contains("=<redacted>"),
            "{fixture}: redaction markers"
        );
    }
}

/// Facts from the real radio, checked against what its web UI showed.
#[test]
fn real_litebeam_facts_match_the_device() {
    let root = fixture_root("lbe-5ac-gen2-wa-8.7.22");
    let mut coverage = Coverage {
        missing: missing_commands(&root),
        ..Coverage::default()
    };
    let facts = parse_artifacts(&raw_artifacts(&root), &mut coverage);
    let system = &facts.system;
    assert_eq!(system.model.as_deref(), Some("LiteBeam 5AC Gen2"));
    assert_eq!(
        system.firmware.as_deref(),
        Some("WA.ar934x.v8.7.22.48486.260227.1959")
    );
    assert_eq!(system.uptime_seconds, Some(143_405));
    // /proc/loadavg wins over the scaled integer mca-status reports.
    assert_eq!(system.loadavg.as_ref().and_then(|l| l.one_min), Some(0.02));
    assert_eq!(system.cpu_load_pct, Some(7.0));
    let radio = facts.radio.expect("radio");
    assert_eq!(radio.mode, Some(RadioMode::Station));
    assert_eq!(radio.frequency_mhz, Some(5285));
    assert_eq!(radio.channel_width_mhz, Some(20));
    assert_eq!(radio.tx_power_dbm, Some(24));
    assert_eq!(radio.signal_dbm, Some(-69));
    assert_eq!(radio.noise_floor_dbm, Some(-89));
    assert_eq!(
        radio.chains.iter().map(|c| c.rssi_dbm).collect::<Vec<_>>(),
        vec![Some(-72), Some(-72)]
    );
    assert_eq!(radio.distance_m, Some(8700));
    assert_eq!(radio.airtime_pct.and_then(|a| a.busy), Some(0.4));
    assert_eq!(radio.tx_rate_mbps, Some(57.8));
    assert_eq!(radio.rx_rate_mbps, Some(115.6));
    let eth0 = facts
        .interfaces
        .iter()
        .find(|i| i.name.as_deref() == Some("eth0"))
        .expect("eth0");
    assert_eq!(eth0.speed_mbps, Some(100));
    assert_eq!(eth0.duplex, Some(Duplex::Full));
    assert!(eth0.mac.is_some());
    assert_eq!(eth0.counters.as_ref().and_then(|c| c.rx_errors), Some(0));
    assert_eq!(facts.services.snmp.enabled, Some(false));
    assert_eq!(facts.services.telnet.enabled, Some(false));
    assert_eq!(facts.services.https.enabled, Some(true));
    // mca-dump exited 127 on this firmware: skipped, never parsed.
    assert!(coverage.missing.iter().any(|m| m == "mca-dump"));
    assert!(!coverage.errors.contains_key("mca-dump"));
    let config = facts.config.expect("config");
    assert!(!config.text.contains("psk=") || config.text.contains("psk=<redacted>"));
    assert!(config.text.contains("unms.uri=<redacted>"));
}

#[test]
fn config_redacts_and_keeps_default_presence_without_value() {
    let f = parse::system_cfg::parse(
        b"snmp.community=public\nusers.1.password=secret\nwireless.1.wpa.psk=secret\nusers.1.name=operator",
    )
    .unwrap();
    assert_eq!(f.services.snmp.community_is_default, Some(true));
    let text = f.config.unwrap().text;
    assert!(!text.contains("secret"));
    assert!(!text.contains("public"));
    assert!(text.contains("users.1.name=operator"));
}

#[test]
fn airos_config_parses_identically_with_crlf_and_lf() {
    // Windows checkouts and some capture paths deliver CRLF. The stored facts,
    // including the redacted config text, must not depend on that.
    let root = fixture_root("synthetic-xw-6.3.6").join("system.cfg");
    let lf = String::from_utf8(std::fs::read(root).unwrap())
        .unwrap()
        .replace("\r\n", "\n");
    let crlf = lf.replace('\n', "\r\n");
    let from_lf = parse::system_cfg::parse(lf.as_bytes()).unwrap();
    let from_crlf = parse::system_cfg::parse(crlf.as_bytes()).unwrap();
    assert_eq!(from_lf, from_crlf);
    assert!(!from_lf.config.unwrap().text.contains('\r'));
}
