//! Borrowed snapshot access with inventory metadata and precomputed indexes.
use nm_core::{
    CredentialProfile, Device, DeviceFamily, DeviceId, DeviceResult, DeviceRole, HostOrIp,
    InterfaceFacts, InterfaceRole, RadioFacts, Site, SiteId, Snapshot,
};
use std::collections::BTreeMap;

/// A deterministic, indexed view of one snapshot. No credentials or network handles.
pub struct SnapshotView<'a> {
    pub snapshot: &'a Snapshot,
    pub previous: Option<&'a Snapshot>,
    inventory: &'a [Device],
    site_records: &'a [Site],
    profiles: &'a [CredentialProfile],
    results: BTreeMap<DeviceId, &'a DeviceResult>,
    pub mac_index: BTreeMap<String, DeviceId>,
    pub ip_index: BTreeMap<String, DeviceId>,
    pub site_index: BTreeMap<SiteId, Vec<DeviceId>>,
}
/// Normalize MAC separators and case for matching independently collected data.
pub fn normalize_mac(mac: &str) -> String {
    mac.to_ascii_lowercase().replace('-', ":")
}
impl<'a> SnapshotView<'a> {
    /// Index only devices present in this snapshot; unscanned inventory never runs rules.
    pub fn new(
        snapshot: &'a Snapshot,
        inventory: &'a [Device],
        sites: &'a [Site],
        profiles: &'a [CredentialProfile],
    ) -> Self {
        let mut v = Self {
            snapshot,
            previous: None,
            inventory,
            site_records: sites,
            profiles,
            results: snapshot
                .device_results
                .iter()
                .map(|r| (r.device_id, r))
                .collect(),
            mac_index: BTreeMap::new(),
            ip_index: BTreeMap::new(),
            site_index: BTreeMap::new(),
        };
        for d in inventory.iter().filter(|d| v.results.contains_key(&d.id)) {
            if let HostOrIp::Ip(ip) = d.management.host {
                v.ip_index.insert(ip.to_string(), d.id);
            }
            if let Some(s) = d.site {
                v.site_index.entry(s).or_default().push(d.id);
            }
            let r = v.results[&d.id];
            for i in &r.facts.interfaces {
                if let Some(mac) = &i.mac {
                    v.mac_index.insert(normalize_mac(mac), d.id);
                }
                for a in &i.addresses {
                    if let Some(ip) = a
                        .split('/')
                        .next()
                        .filter(|p| p.parse::<std::net::IpAddr>().is_ok())
                    {
                        v.ip_index.insert(ip.into(), d.id);
                    }
                }
            }
            for a in &r.facts.addresses {
                if let Some(ip) = &a.address {
                    v.ip_index
                        .insert(ip.split('/').next().unwrap().into(), d.id);
                }
            }
            if let Some(mac) = r.facts.radio.as_ref().and_then(|r| r.mac.as_ref()) {
                v.mac_index.insert(normalize_mac(mac), d.id);
            }
            if let Some(ip) = r.facts.routing.as_ref().and_then(|r| r.router_id.as_ref()) {
                v.ip_index.insert(ip.clone(), d.id);
            }
        }
        v
    }
    /// Snapshot devices in stable inventory order.
    pub fn devices(&self) -> impl Iterator<Item = (&'a Device, &'a DeviceResult)> + '_ {
        self.inventory
            .iter()
            .filter_map(|d| Some((d, *self.results.get(&d.id)?)))
    }
    /// Look up a scanned device and its observations.
    pub fn device(&self, id: DeviceId) -> Option<(&'a Device, &'a DeviceResult)> {
        self.devices().find(|(d, _)| d.id == id)
    }
    /// Scan results from a selected platform family.
    pub fn by_family(
        &self,
        f: DeviceFamily,
    ) -> impl Iterator<Item = (&'a Device, &'a DeviceResult)> + '_ {
        self.devices().filter(move |(d, _)| d.family == f)
    }
    /// Scan results enrolled at a site.
    pub fn by_site(&self, s: SiteId) -> impl Iterator<Item = (&'a Device, &'a DeviceResult)> + '_ {
        self.devices().filter(move |(d, _)| d.site == Some(s))
    }
    /// Devices with observed radio facts.
    pub fn radios(&self) -> impl Iterator<Item = (&'a Device, &'a RadioFacts)> + '_ {
        self.devices()
            .filter_map(|(d, r)| Some((d, r.facts.radio.as_ref()?)))
    }
    /// `EdgeOS` routers and devices explicitly enrolled as routers.
    pub fn routers(&self) -> impl Iterator<Item = (&'a Device, &'a DeviceResult)> + '_ {
        self.devices()
            .filter(|(d, _)| d.family == DeviceFamily::EdgeOs || d.role == Some(DeviceRole::Router))
    }
    /// Site records referenced by this snapshot.
    pub fn sites(&self) -> impl Iterator<Item = &'a Site> + '_ {
        self.site_records
            .iter()
            .filter(|s| self.site_index.contains_key(&s.id))
    }
    /// Metadata of profiles assigned to scanned devices; secret material is inaccessible.
    pub fn profiles_in_use(&self) -> impl Iterator<Item = &'a CredentialProfile> + '_ {
        self.profiles.iter().filter(|p| {
            self.devices()
                .any(|(d, _)| d.credential_profile == Some(p.id))
        })
    }
    /// Role overrides take precedence over inferred observations.
    pub fn interface_role(&self, d: &Device, i: &InterfaceFacts) -> Option<InterfaceRole> {
        i.name
            .as_ref()
            .and_then(|n| d.interface_roles.get(n))
            .copied()
            .or(i.role)
    }
}
