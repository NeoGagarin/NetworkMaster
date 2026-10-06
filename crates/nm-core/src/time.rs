use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};
use time::{format_description::well_known::Rfc3339, OffsetDateTime, UtcOffset};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timestamp(OffsetDateTime);

impl Timestamp {
    pub fn now() -> Self {
        Self(OffsetDateTime::now_utc())
    }
    pub fn from_datetime(value: OffsetDateTime) -> Self {
        Self(value.to_offset(UtcOffset::UTC))
    }
    pub fn as_datetime(self) -> OffsetDateTime {
        self.0
    }
}
impl std::fmt::Display for Timestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0.format(&Rfc3339).map_err(|_| std::fmt::Error)?)
    }
}
impl Serialize for Timestamp {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}
impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        OffsetDateTime::parse(&String::deserialize(d)?, &Rfc3339)
            .map(Self::from_datetime)
            .map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn normalizes_to_utc() {
        let ts: Timestamp = serde_json::from_str("\"2026-10-06T12:00:00+08:00\"").unwrap();
        assert_eq!(ts.to_string(), "2026-10-06T04:00:00Z");
    }
}
