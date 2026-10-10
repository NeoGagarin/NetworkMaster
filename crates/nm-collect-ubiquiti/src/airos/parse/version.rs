use super::{text, ParseError};
use serde::{Deserialize, Serialize};
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Version {
    pub platform: String,
    /// Empty when the source is the short `/etc/version` form (`WA.v8.7.22`).
    pub soc: String,
    pub version: String,
    /// Empty when the source is the short form.
    pub build: String,
}
/// Accepts both the long form reported by `mca-status`
/// (`WA.ar934x.v8.7.22.48486.260227.1959`) and the short form that airOS 8
/// writes to `/etc/version` (`WA.v8.7.22`), observed on a `LiteBeam 5AC Gen2`.
pub fn parse(bytes: &[u8]) -> Result<Version, ParseError> {
    let parts: Vec<_> = text(bytes)?.trim().split('.').collect();
    let v = parts
        .iter()
        .position(|p| {
            p.starts_with('v')
                && p.get(1..)
                    .is_some_and(|s| !s.is_empty() && s.chars().all(|c| c.is_ascii_digit()))
        })
        .ok_or_else(|| ParseError("unrecognized firmware version".into()))?;
    if v == 0 || parts.len() < v + 3 {
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
        build: parts.get(v + 3).unwrap_or(&"").to_string(),
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn long_and_short_forms() {
        let long = parse(b"WA.ar934x.v8.7.22.48486.260227.1959\n").unwrap();
        assert_eq!(
            (
                long.platform.as_str(),
                long.soc.as_str(),
                long.version.as_str(),
                long.build.as_str()
            ),
            ("WA", "ar934x", "8.7.22", "48486")
        );
        let short = parse(b"WA.v8.7.22\n").unwrap();
        assert_eq!(
            (
                short.platform.as_str(),
                short.soc.as_str(),
                short.version.as_str(),
                short.build.as_str()
            ),
            ("WA", "", "8.7.22", "")
        );
        assert!(parse(b"garbage").is_err());
        assert!(parse(b"v8.7").is_err());
    }
}
