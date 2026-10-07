//! Consistent report tokenization, with explicit redaction levels.
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::LazyLock};

/// Names hides identity labels; Full additionally hides addresses, MACs and IDs.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum RedactionLevel {
    None,
    Names,
    #[default]
    Full,
}
/// One instance must be reused across a whole report to preserve relationships.
#[derive(Default)]
pub struct Redactor {
    identities: BTreeMap<String, String>,
    addresses: BTreeMap<String, String>,
}
static ADDRESS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:[0-9a-f]{2}(?::[0-9a-f]{2}){5}|(?:\d{1,3}\.){3}\d{1,3}|[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7})\b").unwrap()
});
impl Redactor {
    /// Register identities before rendering so even evidence text is tokenized.
    pub fn register(&mut self, identity: &str, kind: &str) {
        if !identity.is_empty() && !self.identities.contains_key(identity) {
            let n = self
                .identities
                .values()
                .filter(|v| v.starts_with(kind))
                .count()
                + 1;
            self.identities
                .insert(identity.into(), format!("{kind}-{n}"));
        }
    }
    /// Tokenize a string at the chosen level without changing the source facts.
    pub fn redact(&mut self, text: &str, level: RedactionLevel) -> String {
        if level == RedactionLevel::None {
            return text.into();
        }
        let mut entries: Vec<_> = self.identities.iter().collect();
        entries.sort_by_key(|(key, _)| std::cmp::Reverse(key.len()));
        let mut text = text.to_owned();
        for (key, value) in entries {
            text = text.replace(key, value);
        }
        if level == RedactionLevel::Full {
            text = ADDRESS
                .replace_all(&text, |c: &regex::Captures<'_>| {
                    if c[0].parse::<std::net::IpAddr>().is_err()
                        && !(c[0].len() == 17 && c[0].split(':').count() == 6)
                    {
                        return c[0].to_owned();
                    }
                    let n = self.addresses.len() + 1;
                    self.addresses
                        .entry(c[0].to_ascii_lowercase())
                        .or_insert_with(|| format!("address-{n}"))
                        .clone()
                })
                .into_owned();
        }
        text
    }
}
