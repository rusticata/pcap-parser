use std::convert::TryFrom;

use super::{OptionCode, PcapNGOption};

/// Compute the timestamp resolution, in units per second
///
/// Return the resolution, or `None` if the resolution is invalid (for ex. greater than `2^64`)
pub fn build_ts_resolution(ts_resol: u8) -> Option<u64> {
    let ts_mode = ts_resol & 0x80;
    let unit = if ts_mode == 0 {
        // 10^if_tsresol
        // check that if_tsresol <= 19 (10^19 is the largest power of 10 to fit in a u64)
        if ts_resol > 19 {
            return None;
        }
        10u64.pow(ts_resol as u32)
    } else {
        // 2^if_tsresol
        // check that if_tsresol <= 63
        if ts_resol > 63 {
            return None;
        }
        1 << ((ts_resol & 0x7f) as u64)
    };
    Some(unit)
}

/// Given the timestamp parameters, return the timestamp seconds and fractional part (in resolution
/// units)
pub fn build_ts(ts_high: u32, ts_low: u32, ts_offset: u64, resolution: u64) -> (u32, u32) {
    let if_tsoffset = ts_offset;
    let ts: u64 = ((ts_high as u64) << 32) | (ts_low as u64);
    let ts_sec = (if_tsoffset + (ts / resolution)) as u32;
    let ts_fractional = (ts % resolution) as u32;
    (ts_sec, ts_fractional)
}

/// Given the timestamp parameters, return the timestamp as a `f64` value.
///
/// The resolution is given in units per second. In pcap-ng files, it is stored in the
/// Interface Description Block, and can be obtained using [`crate::InterfaceDescriptionBlock::ts_resolution`]
pub fn build_ts_f64(ts_high: u32, ts_low: u32, ts_offset: u64, resolution: u64) -> f64 {
    let ts: u64 = ((ts_high as u64) << 32) | (ts_low as u64);
    let ts_sec = (ts_offset + (ts / resolution)) as u32;
    let ts_fractional = (ts % resolution) as u32;
    // XXX should we round to closest unit?
    ts_sec as f64 + ((ts_fractional as f64) / (resolution as f64))
}

pub(crate) fn if_extract_tsoffset_and_tsresol(options: &[PcapNGOption]) -> (u8, i64) {
    let mut if_tsresol: u8 = 6;
    let mut if_tsoffset: i64 = 0;
    for opt in options {
        match opt.code {
            OptionCode::IfTsresol => {
                if !opt.value.is_empty() {
                    if_tsresol = opt.value[0];
                }
            }
            OptionCode::IfTsoffset => {
                if opt.value.len() >= 8 {
                    let int_bytes =
                        <[u8; 8]>::try_from(&opt.value[..8]).expect("Convert bytes to i64");
                    if_tsoffset = i64::from_le_bytes(int_bytes);
                }
            }
            _ => (),
        }
    }
    (if_tsresol, if_tsoffset)
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::*;

    #[test]
    fn decode_ts() {
        // from https://datatracker.ietf.org/doc/html/draft-ietf-opsawg-pcapng section 4.6 (ISB)
        // '97 c3 04 00 aa 47 ca 64', in Little Endian, decodes to 2012-06-29 07:28:25.298858 UTC.

        const INPUT_HIGH: [u8; 4] = hex!("97 c3 04 00");
        const INPUT_LOW: [u8; 4] = hex!("aa 47 ca 64");
        let ts_high = u32::from_le_bytes(INPUT_HIGH);
        let ts_low = u32::from_le_bytes(INPUT_LOW);
        let ts_offset = 0;
        let resolution = build_ts_resolution(6).unwrap();
        // eprintln!("{ts_high:x?}");

        let (ts_sec, ts_usec) = build_ts(ts_high, ts_low, ts_offset, resolution);
        eprintln!("{ts_sec}:{ts_usec}");

        const EXPECTED_TS_SEC: u32 = 1340954905;
        const EXPECTED_TS_USEC: u32 = 298858;
        // // to obtain the above values value, add "chrono" to dev-dependencies and uncomment:
        // use chrono::DateTime;
        // let dt = DateTime::from_timestamp(ts_sec as i64, ts_usec * 1000).unwrap();
        // assert_eq!(dt.to_string(), "2012-06-29 07:28:25.298858 UTC");
        assert_eq!(ts_sec, EXPECTED_TS_SEC);
        assert_eq!(ts_usec, EXPECTED_TS_USEC);
    }
}
