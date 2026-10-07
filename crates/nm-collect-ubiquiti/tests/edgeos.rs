use nm_collect::allowlist::edgeos;
use nm_collect_ubiquiti::edgeos::{
    collector::{artifact_name, parse_artifacts},
    parse::{
        self,
        config_tree::{ConfigTree, SECRET_LEAVES},
    },
};
use nm_core::*;
use sha2::{Digest, Sha256};

#[test]
fn every_operational_fixture_has_a_golden() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/edgeos/synthetic-er-x-2.0.9");
    for command in edgeos::ALL {
        let name = artifact_name(*command);
        let bytes = std::fs::read(root.join(name)).unwrap();
        let raw = RawArtifact {
            kind: ArtifactKind::Text,
            name: name.into(),
            sha256: Sha256::digest(&bytes).into(),
            bytes,
            redacted: true,
        };
        let mut coverage = Coverage::default();
        let facts = parse_artifacts(&[raw], &mut coverage);
        assert!(coverage.errors.is_empty(), "{name}: {:?}", coverage.errors);
        insta::assert_json_snapshot!(name.replace('.', "_"), facts);
    }
}
#[test]
fn merged_facts_preserve_config_routes_counters_and_pool_totals() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/edgeos/synthetic-er-x-2.0.9");
    let raw: Vec<_> = edgeos::ALL
        .iter()
        .map(|c| {
            let name = artifact_name(*c);
            let bytes = std::fs::read(root.join(name)).unwrap();
            RawArtifact {
                kind: ArtifactKind::Text,
                name: name.into(),
                sha256: Sha256::digest(&bytes).into(),
                bytes,
                redacted: true,
            }
        })
        .collect();
    let mut coverage = Coverage::default();
    let facts = parse_artifacts(&raw, &mut coverage);
    assert!(coverage.errors.is_empty(), "{:?}", coverage.errors);
    let eth0 = facts
        .interfaces
        .iter()
        .find(|i| i.name.as_deref() == Some("eth0"))
        .unwrap();
    assert_eq!(eth0.role, Some(InterfaceRole::Wan));
    assert_eq!(eth0.counters.as_ref().unwrap().rx_packets, Some(100));
    assert_eq!(
        facts.routing.as_ref().unwrap().router_id.as_deref(),
        Some("192.0.2.1")
    );
    assert_eq!(facts.routing.as_ref().unwrap().routes.len(), 3);
    assert_eq!(facts.dhcp.as_ref().unwrap().pools[0].leased, Some(95));
    assert_eq!(
        facts.firewall.as_ref().unwrap().rule_sets[0]
            .default_action
            .as_deref(),
        Some("drop")
    );
    assert_eq!(
        facts.firewall.as_ref().unwrap().rule_sets[0].rules[0].packets,
        Some(30)
    );
    insta::assert_json_snapshot!("merged_edgeos", facts);
}
#[test]
fn every_secret_leaf_and_crypt_is_removed_before_serialization() {
    for leaf in SECRET_LEAVES {
        let original=format!("set system login user operator {leaf} 'planted-secret'\nset system host-name 'router name'\n");
        let tree = ConfigTree::parse(original.as_bytes()).unwrap();
        let serialized = tree.serialize();
        assert!(!serialized.contains("planted-secret"), "{leaf}");
        assert_eq!(tree.secrets_removed, 1);
        assert_eq!(
            tree.paths,
            ConfigTree::parse(serialized.as_bytes()).unwrap().paths
        );
    }
    for hash in [
        "$1$salt$abcdef",
        "$5$salt$abcdef",
        "$6$rounds=5000$salt$abcdef",
    ] {
        let input = format!("set arbitrary value '{hash}'\n");
        let tree = ConfigTree::parse(input.as_bytes()).unwrap();
        assert!(!tree.serialize().contains(hash));
    }
    let input=b"set service snmp community 'public' authorization 'ro'\nset system host-name 'customer'\n";
    let facts = parse::config_tree::parse(input).unwrap();
    assert_eq!(facts.services.snmp.community_is_default, Some(true));
    assert!(!facts.config.unwrap().text.contains("public"));
}
#[test]
fn quotes_duplicates_and_config_protocol_branches_round_trip() {
    let input=b"set system host-name 'tower '\\''A'\\'''\nset protocols ospf area 0 network '10.0.0.0/24'\nset system ntp server 192.0.2.1\nset system ntp server 192.0.2.2\nset system ntp server 192.0.2.1\n";
    let tree = ConfigTree::parse(input).unwrap();
    assert!(tree.contains(&["protocols", "ospf"]));
    assert!(!tree.contains(&["protocols", "bgp"]));
    assert_eq!(
        tree.paths,
        ConfigTree::parse(tree.serialize().as_bytes())
            .unwrap()
            .paths
    );
    for invalid in [
        b"".as_slice(),
        b"set system host-name 'unfinished",
        b"configure",
    ] {
        assert!(ConfigTree::parse(invalid).is_err());
    }
}
#[test]
fn ospf_states_and_unknown_offload_are_not_coerced() {
    for (name, state) in [
        ("Full/DR", OspfState::Full),
        ("2-Way/DROther", OspfState::TwoWay),
        ("ExStart/DR", OspfState::ExStart),
        ("Init/DR", OspfState::Init),
    ] {
        let input=format!("Neighbor ID Pri State Dead Time Address Interface RXmtL RqstL DBsmL\n192.0.2.2 1 {name} 30s 192.0.2.2 eth1 0 0 0\n");
        assert_eq!(
            parse::ospf_neighbor(input.as_bytes())
                .unwrap()
                .routing
                .unwrap()
                .ospf_neighbors[0]
                .state,
            Some(state)
        );
    }
    let offload = parse::offload(b"IPv4\n forwarding: enabled\n")
        .unwrap()
        .system
        .offload
        .unwrap();
    assert_eq!(offload.ipv6_forwarding, None);
    assert_eq!(offload.ipv4_forwarding, Some(true));
}
