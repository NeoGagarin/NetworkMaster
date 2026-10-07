use super::{text, InterfaceCounters, InterfaceFacts, ParseError, Result};
pub fn parse(bytes: &[u8]) -> Result<Vec<InterfaceFacts>, ParseError> {
    let mut result = Vec::new();
    for line in text(bytes)?.lines() {
        let Some((name, values)) = line.split_once(':') else {
            continue;
        };
        let v: Vec<u64> = values
            .split_whitespace()
            .map(str::parse)
            .collect::<Result<_, _>>()
            .map_err(|_| ParseError("invalid interface counter".into()))?;
        if v.len() < 16 {
            return Err(ParseError("incomplete interface counters".into()));
        }
        result.push(InterfaceFacts {
            name: Some(name.trim().into()),
            counters: Some(InterfaceCounters {
                rx_bytes: Some(v[0]),
                rx_packets: Some(v[1]),
                rx_errors: Some(v[2]),
                rx_dropped: Some(v[3]),
                tx_bytes: Some(v[8]),
                tx_packets: Some(v[9]),
                tx_errors: Some(v[10]),
                tx_dropped: Some(v[11]),
            }),
            ..InterfaceFacts::default()
        });
    }
    Ok(result)
}
