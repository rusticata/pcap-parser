use nom::bytes::streaming::take;
use nom::IResult;

use crate::utils::array_ref4;
use crate::PcapError;

/// Container for network data in legacy Pcap files
#[derive(Debug)]
pub struct LegacyPcapBlock<'a> {
    pub ts_sec: u32,
    pub ts_usec: u32,
    pub caplen: u32,
    pub origlen: u32,
    pub data: &'a [u8],
}

/// Read a PCAP record header and data
///
/// Each PCAP record starts with a small header, and is followed by packet data.
/// The packet data format depends on the LinkType.
pub fn parse_pcap_frame(i: &[u8]) -> IResult<&[u8], LegacyPcapBlock, PcapError<&[u8]>> {
    if i.len() < 16 {
        return Err(nom::Err::Incomplete(nom::Needed::new(16 - i.len())));
    }
    let ts_sec = u32::from_le_bytes(*array_ref4(i, 0));
    let ts_usec = u32::from_le_bytes(*array_ref4(i, 4));
    let caplen = u32::from_le_bytes(*array_ref4(i, 8));
    let origlen = u32::from_le_bytes(*array_ref4(i, 12));
    let (i, data) = take(caplen as usize)(&i[16..])?;
    let block = LegacyPcapBlock {
        ts_sec,
        ts_usec,
        caplen,
        origlen,
        data,
    };
    Ok((i, block))
}

/// Read a PCAP record header and data (big-endian)
///
/// Each PCAP record starts with a small header, and is followed by packet data.
/// The packet data format depends on the LinkType.
pub fn parse_pcap_frame_be(i: &[u8]) -> IResult<&[u8], LegacyPcapBlock, PcapError<&[u8]>> {
    if i.len() < 16 {
        return Err(nom::Err::Incomplete(nom::Needed::new(16 - i.len())));
    }
    let ts_sec = u32::from_be_bytes(*array_ref4(i, 0));
    let ts_usec = u32::from_be_bytes(*array_ref4(i, 4));
    let caplen = u32::from_be_bytes(*array_ref4(i, 8));
    let origlen = u32::from_be_bytes(*array_ref4(i, 12));
    let (i, data) = take(caplen as usize)(&i[16..])?;
    let block = LegacyPcapBlock {
        ts_sec,
        ts_usec,
        caplen,
        origlen,
        data,
    };
    Ok((i, block))
}

/// Read a PCAP record header and data ("modified" pcap format)
///
/// Each PCAP record starts with a small header, and is followed by packet data.
/// The packet data format depends on the LinkType.
pub fn parse_pcap_frame_modified(i: &[u8]) -> IResult<&[u8], LegacyPcapBlock, PcapError<&[u8]>> {
    if i.len() < 24 {
        return Err(nom::Err::Incomplete(nom::Needed::new(24 - i.len())));
    }
    let ts_sec = u32::from_le_bytes(*array_ref4(i, 0));
    let ts_usec = u32::from_le_bytes(*array_ref4(i, 4));
    let caplen = u32::from_le_bytes(*array_ref4(i, 8));
    let origlen = u32::from_le_bytes(*array_ref4(i, 12));
    let (i, data) = take(caplen as usize)(&i[24..])?;
    let block = LegacyPcapBlock {
        ts_sec,
        ts_usec,
        caplen,
        origlen,
        data,
    };
    Ok((i, block))
}
