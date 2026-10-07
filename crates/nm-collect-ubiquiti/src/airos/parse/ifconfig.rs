use super::{text, InterfaceFacts, ParseError, Result};
use regex::Regex;
pub fn parse(bytes: &[u8]) -> Result<Vec<InterfaceFacts>, ParseError> {
    let s = text(bytes)?;
    let mac = Regex::new(r"(?i)(?:HWaddr|ether)\s+([0-9a-f:]{17})").unwrap();
    let ip = Regex::new(r"inet (?:addr:)?([\d.]+)").unwrap();
    let mut interfaces = Vec::new();
    let mut current = String::new();
    let flush = |s: &str, interfaces: &mut Vec<InterfaceFacts>| {
        if s.is_empty() {
            return;
        }
        let name = s
            .split_whitespace()
            .next()
            .unwrap_or("")
            .trim_end_matches(':');
        interfaces.push(InterfaceFacts {
            name: Some(name.into()),
            mac: mac.captures(s).map(|c| c[1].into()),
            admin_up: Some(s.split([' ', '\n', ',', '<', '>']).any(|w| w == "UP")),
            oper_up: Some(s.contains("RUNNING")),
            addresses: ip.captures_iter(s).map(|c| c[1].into()).collect(),
            ..InterfaceFacts::default()
        });
    };
    for line in s.lines() {
        if !line.starts_with(char::is_whitespace) && !line.is_empty() {
            flush(&current, &mut interfaces);
            current.clear();
        }
        current.push_str(line);
        current.push('\n');
    }
    flush(&current, &mut interfaces);
    if interfaces.is_empty() {
        return Err(ParseError("no interface observations".into()));
    }
    Ok(interfaces)
}
