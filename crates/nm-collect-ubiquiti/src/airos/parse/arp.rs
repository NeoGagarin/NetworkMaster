use super::{text, NeighborFacts, ParseError, Result};
pub fn parse(bytes: &[u8]) -> Result<Vec<NeighborFacts>, ParseError> {
    let mut result = Vec::new();
    for line in text(bytes)?.lines().skip(1) {
        let cols: Vec<_> = line.split_whitespace().collect();
        if cols.len() < 6 {
            return Err(ParseError("incomplete ARP entry".into()));
        }
        if cols[2] == "0x0" || cols[3] == "00:00:00:00:00:00" {
            continue;
        }
        if cols[0].parse::<std::net::IpAddr>().is_err() {
            return Err(ParseError("invalid ARP address".into()));
        }
        result.push(NeighborFacts {
            protocol: Some("arp".into()),
            address: Some(cols[0].into()),
            mac: Some(cols[3].into()),
            interface: Some(cols[5].into()),
            ..NeighborFacts::default()
        });
    }
    Ok(result)
}
