use nm_collect_ubiquiti::airos::{collector::parse_artifacts, parse};
use nm_core::*;
use sha2::{Digest, Sha256};
#[test]
fn parser_goldens_for_both_firmware_shapes() {
    for fixture in ["synthetic-xw-6.3.6", "synthetic-wa-8.7.11"] {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/airos")
            .join(fixture);
        let read = |f: &str| std::fs::read(root.join(f)).unwrap();
        macro_rules! golden {
            ($name:literal,$value:expr) => {
                insta::assert_json_snapshot!(format!("{fixture}_{}", $name), $value.unwrap());
            };
        }
        golden!("version", parse::version::parse(&read("version.txt")));
        golden!("board", parse::board_info::parse(&read("board-info.txt")));
        golden!("status", parse::mca_status::parse(&read("mca-status.txt")));
        golden!("dump", parse::mca_dump::parse(&read("mca-dump.json")));
        golden!("stations", parse::wstalist::parse(&read("wstalist.json")));
        golden!("config", parse::system_cfg::parse(&read("system.cfg")));
        golden!("iwconfig", parse::iwconfig::parse(&read("iwconfig.txt")));
        golden!("ifconfig", parse::ifconfig::parse(&read("ifconfig.txt")));
        golden!(
            "counters",
            parse::proc_net_dev::parse(&read("proc-net-dev.txt"))
        );
        golden!("arp", parse::arp::parse(&read("arp.txt")));
        golden!("uptime", parse::system::uptime(&read("uptime.txt")));
        golden!("free", parse::system::free(&read("free.txt")));
        golden!("loadavg", parse::system::loadavg(&read("loadavg.txt")));
        let raw: Vec<_> = std::fs::read_dir(&root)
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
        let facts = parse_artifacts(&raw, &mut Coverage::default());
        insta::assert_json_snapshot!(format!("{fixture}_merged"), facts);
        assert_eq!(facts.radio.unwrap().channel_width_mhz, Some(40));
        assert!(facts.interfaces[0].mac.is_some());
        assert!(!facts.config.unwrap().text.contains("hunter2"));
    }
}
#[test]
fn config_redacts_and_keeps_default_presence_without_value() {
    let f=parse::system_cfg::parse(b"snmp.community=public\nusers.1.password=secret\nwireless.1.wpa.psk=secret\nusers.1.name=operator").unwrap();
    assert_eq!(f.services.snmp.community_is_default, Some(true));
    let config = f.config.unwrap();
    assert!(!config.text.contains("secret"));
    assert!(!config.text.contains("=public"));
    assert!(config.text.contains("operator"));
    assert_eq!(config.secrets_removed, 3);
}
#[test]
fn optional_vendor_fields_unknown_fields_and_invalid_input() {
    assert!(parse::mca_status::parse(b"future=value").is_ok());
    assert!(parse::mca_dump::parse(b"{\"future\":1}").is_ok());
    assert!(parse::wstalist::parse(b"[]").unwrap().is_empty());
    assert!(parse::version::parse(b"invalid").is_err());
    assert!(parse::mca_dump::parse(b"not json").is_err());
    assert!(parse::proc_net_dev::parse(b"eth0: 1 nope").is_err());
}
