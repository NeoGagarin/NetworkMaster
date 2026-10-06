use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};
use ulid::Ulid;

macro_rules! id {
    ($($name:ident),+ $(,)?) => {$ (
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(Ulid);
        impl $name { pub fn new() -> Self { Self(Ulid::new()) } }
        impl Default for $name { fn default() -> Self { Self::new() } }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { self.0.fmt(f) }
        }
        impl FromStr for $name {
            type Err = ulid::DecodeError;
            fn from_str(s: &str) -> Result<Self, Self::Err> { s.parse().map(Self) }
        }
    )+};
}
id!(
    DeviceId,
    SiteId,
    CredentialProfileId,
    SnapshotId,
    FindingId,
    AiSessionId,
    JobId
);

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn round_trip() {
        let id = DeviceId::new();
        assert_eq!(id, id.to_string().parse().unwrap());
        assert_eq!(
            id,
            serde_json::from_str(&serde_json::to_string(&id).unwrap()).unwrap()
        );
    }
}
