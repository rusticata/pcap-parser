use winnow::bytes::take;
use winnow::error::{ErrMode, Needed};
use winnow::number::{be_i32, be_u16, be_u32, le_i32, le_u16, le_u32};
use winnow::stream::{AsBytes, Stream, StreamIsPartial};
use winnow::IResult;

use super::{LegacyPcapBlock, PcapHeader};
use crate::{Input, Linktype, PcapError};

/// Read a PCAP record header and data
///
/// Each PCAP record starts with a small header, and is followed by packet data.
/// The packet data format depends on the LinkType.
pub fn parse_pcap_frame<'i, I>(i: I) -> IResult<I, LegacyPcapBlock<I::Slice>, PcapError<I>>
where
    I: Stream<Token = u8> + 'i,
    I: StreamIsPartial,
    <I as Stream>::Slice: AsBytes,
{
    if i.eof_offset() < 16 {
        return Err(ErrMode::Incomplete(Needed::new(16 - i.eof_offset())));
    }
    let (i, ts_sec) = le_u32(i)?;
    let (i, ts_usec) = le_u32(i)?;
    let (i, caplen) = le_u32(i)?;
    let (i, origlen) = le_u32(i)?;
    let (i, data) = take(caplen as usize)(i)?;
    let block = LegacyPcapBlock {
        ts_sec,
        ts_usec,
        caplen,
        origlen,
        data,
    };
    Ok((i, block))
}

/// Read a PCAP record header and data
///
/// Each PCAP record starts with a small header, and is followed by packet data.
/// The packet data format depends on the LinkType.
pub fn parse_pcap_frame_u8(i: Input) -> IResult<Input, LegacyPcapBlock<&[u8]>, PcapError<Input>> {
    if i.len() < 16 {
        return Err(ErrMode::Incomplete(Needed::new(16 - i.eof_offset())));
    }
    let (i, ts_sec) = le_u32(i)?;
    let (i, ts_usec) = le_u32(i)?;
    let (i, caplen) = le_u32(i)?;
    let (i, origlen) = le_u32(i)?;
    let (i, data) = take(caplen as usize)(i)?;
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
pub fn parse_pcap_frame_be<'i, I>(i: I) -> IResult<I, LegacyPcapBlock<I::Slice>, PcapError<I>>
where
    I: Stream<Token = u8> + 'i,
    I: StreamIsPartial,
    <I as Stream>::Slice: AsBytes,
{
    if i.eof_offset() < 16 {
        return Err(ErrMode::Incomplete(Needed::new(16 - i.eof_offset())));
    }
    let (i, ts_sec) = be_u32(i)?;
    let (i, ts_usec) = be_u32(i)?;
    let (i, caplen) = be_u32(i)?;
    let (i, origlen) = be_u32(i)?;
    let (i, data) = take(caplen as usize)(i)?;
    let block = LegacyPcapBlock {
        ts_sec,
        ts_usec,
        caplen,
        origlen,
        data,
    };
    Ok((i, block))
}

/// Read the PCAP global header
///
/// The global header contains the PCAP description and options
pub fn parse_pcap_header<'i, I>(i: I) -> IResult<I, PcapHeader, PcapError<I>>
where
    I: Stream<Token = u8> + 'i,
    I: StreamIsPartial,
    <I as Stream>::Slice: AsBytes,
{
    let (i, magic_number) = le_u32(i)?;
    match magic_number {
        0xa1b2_c3d4 | 0xa1b2_3c4d => {
            let (i, version_major) = le_u16(i)?;
            let (i, version_minor) = le_u16(i)?;
            let (i, thiszone) = le_i32(i)?;
            let (i, sigfigs) = le_u32(i)?;
            let (i, snaplen) = le_u32(i)?;
            let (i, network) = le_i32(i)?;
            let header = PcapHeader {
                magic_number,
                version_major,
                version_minor,
                thiszone,
                sigfigs,
                snaplen,
                network: Linktype(network),
            };
            Ok((i, header))
        }
        0xd4c3_b2a1 | 0x4d3c_b2a1 => {
            let (i, version_major) = be_u16(i)?;
            let (i, version_minor) = be_u16(i)?;
            let (i, thiszone) = be_i32(i)?;
            let (i, sigfigs) = be_u32(i)?;
            let (i, snaplen) = be_u32(i)?;
            let (i, network) = be_i32(i)?;
            let header = PcapHeader {
                magic_number,
                version_major,
                version_minor,
                thiszone,
                sigfigs,
                snaplen,
                network: Linktype(network),
            };
            Ok((i, header))
        }
        _ => Err(ErrMode::Backtrack(PcapError::HeaderNotRecognized)),
    }
}
