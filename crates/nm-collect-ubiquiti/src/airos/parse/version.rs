use super::{text, ParseError};
use serde::{Deserialize, Serialize};
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Version {
    pub platform: String,
    pub soc: String,
    pub version: String,
    pub build: String,
}
pub fn parse(bytes: &[u8]) -> Result<Version, ParseError> {
    let parts: Vec<_> = text(bytes)?.trim().split('.').collect();
    let v = parts
        .iter()
        .position(|p| {
            p.starts_with('v')
                && p.get(1..)
                    .is_some_and(|s| s.chars().all(|c| c.is_ascii_digit()))
        })
        .ok_or_else(|| ParseError("unrecognized firmware version".into()))?;
    if v == 0 || parts.len() < v + 4 {
        return Err(ParseError("incomplete firmware version".into()));
    }
    Ok(Version {
        platform: parts[0].into(),
        soc: parts.get(1).filter(|_| v > 1).unwrap_or(&"").to_string(),
        version: format!(
            "{}.{}.{}",
            parts[v].trim_start_matches('v'),
            parts[v + 1],
            parts[v + 2]
        ),
        build: parts[v + 3].into(),
    })
}
