use super::{text, DeviceFacts, ParseError, RadioFacts, Result};
use regex::Regex;
pub fn parse(bytes: &[u8]) -> Result<DeviceFacts, ParseError> {
    let s = text(bytes)?;
    let capture = |pattern: &str| {
        Regex::new(pattern)
            .unwrap()
            .captures(s)
            .and_then(|c| c[1].parse::<f64>().ok())
    };
    let freq = capture(r"Frequency[:=]\s*([\d.]+)");
    let bitrate = capture(r"Bit Rate[:=]\s*([\d.]+)");
    let signal = capture(r"Signal level[:=]\s*(-?\d+)");
    if freq.is_none() && bitrate.is_none() && signal.is_none() {
        return Err(ParseError("no wireless observations".into()));
    }
    Ok(DeviceFacts {
        radio: Some(RadioFacts {
            frequency_mhz: freq.map(|f| {
                if f < 100.0 {
                    (f * 1000.0)
                        .round()
                        .to_string()
                        .parse::<u32>()
                        .ok()
                        .unwrap_or(0)
                } else {
                    f.round().to_string().parse::<u32>().ok().unwrap_or(0)
                }
            }),
            tx_rate_mbps: bitrate.and_then(|n| n.to_string().parse::<f32>().ok()),
            signal_dbm: signal.and_then(|n| n.to_string().parse::<i16>().ok()),
            ..RadioFacts::default()
        }),
        ..DeviceFacts::default()
    })
}
