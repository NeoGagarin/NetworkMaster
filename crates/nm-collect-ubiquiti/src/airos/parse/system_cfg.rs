use super::{
    flag, integer, key_values, string, text, ConfigFormat, DeviceFacts, DeviceFamily,
    InterfaceFacts, ParseError, RadioFacts, RedactedConfig, Result, RouteFacts, RoutingFacts,
    ServiceFacts, ServicesFacts, SnmpFacts, Value,
};
use nm_collect::scrub::scrub_secrets;
#[allow(clippy::field_reassign_with_default)]
pub fn parse(bytes: &[u8]) -> Result<DeviceFacts, ParseError> {
    let v = key_values(bytes)?;
    let (bytes, removed) = scrub_secrets(DeviceFamily::AirOs, "system.cfg", bytes);
    let get = |key: &str| v.get(key).map_or(Value::Null, |s| Value::String(s.clone()));
    let svc = |key: &str| ServiceFacts {
        enabled: flag(&get(key)),
        ..ServiceFacts::default()
    };
    let mut f = DeviceFacts::default();
    f.config = Some(RedactedConfig {
        format: ConfigFormat::KeyValue,
        text: text(&bytes)?.to_owned(),
        secrets_removed: removed,
    });
    f.services = ServicesFacts {
        ssh: svc("sshd.status"),
        telnet: svc("telnetd.status"),
        http: ServiceFacts {
            port: integer(&get("httpd.port")),
            ..svc("httpd.status")
        },
        https: svc("httpd.https.status"),
        upnp: svc("upnpd.status"),
        discovery: svc("discovery.status"),
        ntp: svc("ntpclient.status"),
        snmp: SnmpFacts {
            enabled: flag(&get("snmp.status")),
            community_present: Some(v.contains_key("snmp.community")),
            community_is_default: v
                .get("snmp.community")
                .filter(|s| s.as_str() != "<redacted>")
                .map(|s| s == "public" || s == "private"),
            ..SnmpFacts::default()
        },
        ..ServicesFacts::default()
    };
    f.system.ntp_servers = v
        .iter()
        .filter(|(k, _)| k.starts_with("ntpclient.") && k.ends_with(".server"))
        .map(|(_, v)| v.clone())
        .collect();
    f.system.netrole = v.get("netmode").cloned();
    f.system.hostname = v.get("resolv.host.1.name").cloned();
    f.radio = Some(RadioFacts {
        ssid: string(&get("wireless.1.ssid")),
        security: string(&get("wireless.1.security")),
        ssid_hidden: flag(&get("wireless.1.hide_ssid")),
        country_code: integer(&get("radio.1.countrycode")),
        country_obey: flag(&get("radio.1.obey")),
        frequency_mhz: integer(&get("radio.1.freq")),
        channel_width_mhz: integer(&get("radio.1.chanbw")),
        tx_power_dbm: integer(&get("radio.1.txpower")),
        ..RadioFacts::default()
    });
    for (key, name) in &v {
        if key.starts_with("netconf.") && key.ends_with(".devname") {
            let prefix = key.trim_end_matches("devname");
            let ip = v.get(&format!("{prefix}ip"));
            let mask = v.get(&format!("{prefix}netmask"));
            f.interfaces.push(InterfaceFacts {
                name: Some(name.clone()),
                admin_up: flag(&get(&format!("{prefix}status"))),
                addresses: ip
                    .map(|ip| vec![mask.map_or_else(|| ip.clone(), |m| format!("{ip}/{m}"))])
                    .unwrap_or_default(),
                ..InterfaceFacts::default()
            });
        }
        if key.starts_with("route.") && key.strip_suffix(".ip").is_some() {
            let prefix = key.trim_end_matches("ip");
            f.routing
                .get_or_insert_with(RoutingFacts::default)
                .routes
                .push(RouteFacts {
                    prefix: Some(
                        if name == "0.0.0.0"
                            && v.get(&format!("{prefix}netmask"))
                                .is_some_and(|s| s == "0.0.0.0")
                        {
                            "0.0.0.0/0".into()
                        } else {
                            name.clone()
                        },
                    ),
                    next_hop: v.get(&format!("{prefix}gateway")).cloned(),
                    interface: v.get(&format!("{prefix}devname")).cloned(),
                    ..RouteFacts::default()
                });
        }
    }
    Ok(f)
}
