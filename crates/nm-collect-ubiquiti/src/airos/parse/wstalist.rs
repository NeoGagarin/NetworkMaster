use super::{
    airmax, chains, counters, integer, num, string, ParseError, RemoteRadioFacts, Result,
    StationFacts, Value,
};
pub fn parse(bytes: &[u8]) -> Result<Vec<StationFacts>, ParseError> {
    let stations: Vec<Value> = serde_json::from_slice(bytes)?;
    Ok(stations
        .iter()
        .map(|s| {
            let remote = &s["remote"];
            StationFacts {
                mac: string(&s["mac"]),
                hostname: string(&s["name"]).or_else(|| string(&remote["hostname"])),
                signal_dbm: integer(&s["signal"]),
                noise_floor_dbm: integer(&s["noisefloor"]),
                ccq_pct: integer(&s["ccq"]),
                tx_rate_mbps: num(&s["tx"])
                    .and_then(|n| n.to_string().parse::<f32>().ok())
                    .filter(|n| n.is_finite()),
                rx_rate_mbps: num(&s["rx"])
                    .and_then(|n| n.to_string().parse::<f32>().ok())
                    .filter(|n| n.is_finite()),
                chains: chains(&s["chainrssi"]),
                distance_m: integer(&s["distance"]),
                uptime_seconds: integer(&s["uptime"]),
                airmax: airmax(&s["airmax"]),
                remote: remote.as_object().map(|_| RemoteRadioFacts {
                    hostname: string(&remote["hostname"]),
                    platform: string(&remote["platform"]),
                    version: string(&remote["version"]),
                    signal_dbm: integer(&remote["signal"]),
                    noise_floor_dbm: integer(&remote["noisefloor"]),
                    tx_power_dbm: integer(&remote["tx_power"]),
                    rx_chainmask: integer(&remote["rx_chainmask"]),
                }),
                counters: s["stats"].as_object().map(|_| counters(&s["stats"])),
                ..StationFacts::default()
            }
        })
        .collect())
}
