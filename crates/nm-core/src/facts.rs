use serde::{Deserialize, Serialize};

// Optional scalars and empty collections represent unavailable observations.
macro_rules! facts {
    ($name:ident { $($field:ident: $ty:ty),* $(,)? }) => {
        #[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
        #[serde(default)]
        pub struct $name { $(pub $field: $ty),* }
    };
}
facts!(DeviceFacts {
    system: SystemFacts, interfaces: Vec<InterfaceFacts>, addresses: Vec<AddressFacts>,
    radio: Option<RadioFacts>, routing: Option<RoutingFacts>, services: ServicesFacts,
    dhcp: Option<DhcpFacts>, firewall: Option<FirewallFacts>, config: Option<RedactedConfig>,
    neighbors: Vec<NeighborFacts>,
});
facts!(SystemFacts {
    hostname: Option<String>, model: Option<String>, firmware: Option<String>,
    uptime_seconds: Option<u64>, loadavg: Option<LoadAverage>, cpu_count: Option<u32>,
    memory: Option<MemoryFacts>, serial: Option<String>, ntp_servers: Vec<String>,
    offload: Option<OffloadFacts>,
    ssh_host_key_changed: Option<bool>, ssh_legacy_algorithms: Option<bool>,
    cpu_load_pct: Option<f64>, genuine: Option<bool>,
    platform:Option<String>, soc:Option<String>, firmware_build:Option<String>, board_id:Option<String>, netrole:Option<String>,
});
facts!(LoadAverage { one_min: Option<f64>, five_min: Option<f64>, fifteen_min: Option<f64> });
facts!(MemoryFacts { total_bytes: Option<u64>, available_bytes: Option<u64>, free_bytes: Option<u64> });
facts!(InterfaceFacts {
    name: Option<String>, mac: Option<String>, description: Option<String>,
    admin_up: Option<bool>, oper_up: Option<bool>, speed_mbps: Option<u32>,
    duplex: Option<Duplex>, counters: Option<InterfaceCounters>, addresses: Vec<String>,
    role: Option<InterfaceRole>, role_confidence: Option<crate::Confidence>,
    firewall_in: Option<String>, firewall_out: Option<String>, firewall_local: Option<String>,
});
facts!(InterfaceCounters {
    rx_bytes: Option<u64>, tx_bytes: Option<u64>, rx_packets: Option<u64>, tx_packets: Option<u64>,
    rx_errors: Option<u64>, tx_errors: Option<u64>, rx_dropped: Option<u64>, tx_dropped: Option<u64>,
});
facts!(AddressFacts { address: Option<String>, interface: Option<String>, dynamic: Option<bool> });
facts!(RadioFacts {
    mode: Option<RadioMode>, ssid: Option<String>, frequency_mhz: Option<u32>,
    channel_width_mhz: Option<u16>, tx_power_dbm: Option<i16>, noise_floor_dbm: Option<i16>,
    chains: Vec<ChainSignal>, ccq_pct: Option<u8>, airtime_pct: Option<AirtimeFacts>,
    tx_rate_mbps: Option<f32>, rx_rate_mbps: Option<f32>, stations: Vec<StationFacts>,
    airmax: Option<AirMaxFacts>, distance_m: Option<u32>, mcs: Option<u8>,
    signal_dbm: Option<i16>, polling_enabled: Option<bool>,
    mac: Option<String>, throughput_mbps: Option<f64>, security:Option<String>, ssid_hidden:Option<bool>, country_code:Option<u16>, country_obey:Option<bool>,
});
facts!(ChainSignal { chain: Option<u8>, rssi_dbm: Option<i16> });
facts!(AirtimeFacts { tx: Option<f32>, rx: Option<f32>, busy: Option<f32> });
facts!(StationFacts {
    mac: Option<String>, hostname: Option<String>, address: Option<String>, model: Option<String>,
    chains: Vec<ChainSignal>, ccq_pct: Option<u8>, tx_rate_mbps: Option<f32>,
    rx_rate_mbps: Option<f32>, distance_m: Option<u32>, mcs: Option<u8>,
    signal_dbm: Option<i16>, noise_floor_dbm: Option<i16>, uptime_seconds: Option<u64>,
    airmax: Option<AirMaxFacts>, remote: Option<RemoteRadioFacts>, counters: Option<InterfaceCounters>,
});
facts!(RemoteRadioFacts {
    hostname: Option<String>, platform: Option<String>, version: Option<String>,
    signal_dbm: Option<i16>, noise_floor_dbm: Option<i16>, tx_power_dbm: Option<i16>, rx_chainmask: Option<u8>,
});
facts!(AirMaxFacts { quality_pct: Option<u8>, capacity_pct: Option<u8>, priority: Option<u8> });
facts!(RoutingFacts {
    routes: Vec<RouteFacts>, ospf_neighbors: Vec<OspfNeighbor>, ospf_interfaces: Vec<OspfInterface>,
    bgp_peers: Vec<BgpPeer>, router_id: Option<String>, protocol_counts: std::collections::BTreeMap<String,u32>,
});
facts!(RouteFacts {
    prefix: Option<String>, protocol: Option<String>, next_hop: Option<String>,
    interface: Option<String>, metric: Option<u32>,
});
facts!(OspfNeighbor {
    router_id: Option<String>, state: Option<OspfState>, address: Option<String>, interface: Option<String>,
});
facts!(OspfInterface {
    name: Option<String>, area: Option<String>, cost: Option<u32>, state: Option<String>,
    dr: Option<String>, bdr: Option<String>, hello_seconds: Option<u32>, dead_seconds: Option<u32>,
});
facts!(BgpPeer {
    address: Option<String>, remote_as: Option<u32>, state: Option<BgpState>, prefixes_received: Option<u32>,
});
facts!(OffloadFacts {
    ipv4_forwarding: Option<bool>, ipv4_vlan: Option<bool>, ipv4_pppoe: Option<bool>,
    ipv6_forwarding: Option<bool>, ipv6_vlan: Option<bool>, ipv6_pppoe: Option<bool>, ipsec: Option<bool>,
});
facts!(ServicesFacts {
    http: ServiceFacts,
    https: ServiceFacts,
    ssh: ServiceFacts,
    telnet: ServiceFacts,
    snmp: SnmpFacts,
    upnp: ServiceFacts,
    discovery: ServiceFacts,
    ntp: ServiceFacts,
    dhcp_client: ServiceFacts,
    dhcp_server: ServiceFacts,
    pppoe: ServiceFacts,
});
facts!(ServiceFacts { enabled: Option<bool>, port: Option<u16>, listen_addresses: Vec<String> });
facts!(SnmpFacts {
    enabled: Option<bool>, port: Option<u16>, community_present: Option<bool>, community_is_default: Option<bool>,
});
facts!(DhcpFacts { pools: Vec<DhcpPool> });
facts!(DhcpPool { name: Option<String>, size: Option<u32>, leased: Option<u32>, available: Option<u32> });
facts!(FirewallFacts { rule_sets: Vec<FirewallRuleSet>, nat_rules: Vec<FirewallRule>, enabled:Option<bool>, vendor_fields:serde_json::Map<String,serde_json::Value> });
facts!(FirewallRuleSet { name: Option<String>, default_action: Option<String>, rules: Vec<FirewallRule> });
facts!(FirewallRule { number: Option<u32>, action: Option<String>, packets: Option<u64>, bytes: Option<u64> });
facts!(NeighborFacts {
    protocol: Option<String>, mac: Option<String>, address: Option<String>,
    hostname: Option<String>, interface: Option<String>,
});

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct RedactedConfig {
    pub format: ConfigFormat,
    pub text: String,
    pub secrets_removed: u32,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConfigFormat {
    #[default]
    Text,
    Json,
    SetCommands,
    KeyValue,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RadioMode {
    Ap,
    Station,
    PtpMaster,
    PtpSlave,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Duplex {
    Half,
    Full,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum InterfaceRole {
    Lan,
    Wan,
    Management,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OspfState {
    Down,
    Attempt,
    Init,
    TwoWay,
    ExStart,
    Exchange,
    Loading,
    Full,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BgpState {
    Idle,
    Connect,
    Active,
    OpenSent,
    OpenConfirm,
    Established,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_facts_struct_accepts_empty_object() {
        macro_rules! check { ($($ty:ty),+) => { $(
            assert_eq!(serde_json::from_str::<$ty>("{}").unwrap(), <$ty>::default());
        )+ }; }
        check!(
            DeviceFacts,
            SystemFacts,
            LoadAverage,
            MemoryFacts,
            InterfaceFacts,
            InterfaceCounters,
            AddressFacts,
            RadioFacts,
            ChainSignal,
            AirtimeFacts,
            StationFacts,
            AirMaxFacts,
            RoutingFacts,
            RouteFacts,
            OspfNeighbor,
            OspfInterface,
            BgpPeer,
            OffloadFacts,
            ServicesFacts,
            ServiceFacts,
            SnmpFacts,
            DhcpFacts,
            DhcpPool,
            FirewallFacts,
            FirewallRuleSet,
            FirewallRule,
            NeighborFacts,
            RedactedConfig
        );
    }
}
