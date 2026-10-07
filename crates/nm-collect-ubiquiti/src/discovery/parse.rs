use super::DiscoveredDevice;
use std::net::Ipv4Addr;

pub fn parse(bytes: &[u8]) -> Result<DiscoveredDevice, &'static str> {
    if bytes.len() < 4 || ![1, 2].contains(&bytes[0]) || bytes[1] != 0 {
        return Err("invalid discovery header");
    }
    let length = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
    if length + 4 != bytes.len() {
        return Err("invalid discovery length");
    }
    let mut device = DiscoveredDevice::default();
    let mut pos = 4;
    while pos < bytes.len() {
        if bytes.len() - pos < 3 {
            return Err("truncated TLV header");
        }
        let tag = bytes[pos];
        let n = usize::from(u16::from_be_bytes([bytes[pos + 1], bytes[pos + 2]]));
        pos += 3;
        let value = bytes.get(pos..pos + n).ok_or("truncated TLV value")?;
        pos += n;
        device.raw_tags.entry(tag).or_default().push(value.to_vec());
        let string = || {
            String::from_utf8_lossy(value)
                .trim_end_matches('\0')
                .to_owned()
        };
        match tag {
            1 | 2 if value.len() == 10 => {
                device.mac = Some(
                    value[..6]
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<Vec<_>>()
                        .join(":"),
                );
                device.ip = Some(Ipv4Addr::new(value[6], value[7], value[8], value[9]));
            }
            1 if value.len() == 6 => {
                device.mac = Some(
                    value
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<Vec<_>>()
                        .join(":"),
                );
            }
            3 => device.firmware = Some(string()),
            0x0a if value.len() == 4 => {
                device.uptime = Some(u32::from_be_bytes(value.try_into().unwrap()));
            }
            0x0b => device.hostname = Some(string()),
            0x0c if device.model.is_none() => device.model = Some(string()),
            0x14 => device.model = Some(string()),
            0x0d => device.essid = Some(string()),
            0x0e if !value.is_empty() => device.wmode = Some(value[0]),
            _ => {}
        }
    }
    Ok(device)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixture_replies_and_truncation() {
        for (bytes, family) in [
            (
                include_bytes!("../../../../fixtures/discovery/airmax.bin").as_slice(),
                nm_core::DeviceFamily::AirOs,
            ),
            (
                include_bytes!("../../../../fixtures/discovery/airfiber.bin").as_slice(),
                nm_core::DeviceFamily::AirOs,
            ),
            (
                include_bytes!("../../../../fixtures/discovery/edgerouter.bin").as_slice(),
                nm_core::DeviceFamily::EdgeOs,
            ),
        ] {
            let device = parse(bytes).unwrap();
            assert_eq!(device.candidate().unwrap().family, family);
            assert!(!device.candidate().unwrap().enrolled);
            for n in 0..bytes.len() {
                assert!(parse(&bytes[..n]).is_err());
            }
        }
    }
}
