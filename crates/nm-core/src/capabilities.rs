//! Bundled, offline platform capabilities used by rules and future frontends.
use crate::DeviceFamily;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::LazyLock};

/// Features available on one platform family; model restrictions remain explicit.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Capabilities {
    pub routing: Vec<String>,
    pub not_supported: Vec<String>,
    pub services: Vec<String>,
    pub hardware_offload: bool,
    pub offload_models: Vec<String>,
    pub channel_widths: Vec<u16>,
    pub management: Vec<String>,
}
static TABLE: LazyLock<BTreeMap<String, Capabilities>> = LazyLock::new(|| {
    toml::from_str(include_str!("../../nm-analyze/data/capabilities.toml"))
        .expect("bundled capabilities must be valid")
});
impl Capabilities {
    /// Return the bundled capabilities, or None for unsupported families.
    pub fn for_family(family: DeviceFamily) -> Option<&'static Self> {
        TABLE.get(match family {
            DeviceFamily::AirOs => "airos",
            DeviceFamily::EdgeOs => "edgeos",
            _ => return None,
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn edgeos_excludes_eigrp() {
        assert!(Capabilities::for_family(DeviceFamily::EdgeOs)
            .unwrap()
            .not_supported
            .iter()
            .any(|p| p == "eigrp"));
    }
}
