//! PCAP file format
//!
//! See <https://wiki.wireshark.org/Development/LibpcapFileFormat> for details.
//!
//! There are 2 main ways of parsing a PCAP file. The first method is to use
//! [`parse_pcap`](../fn.parse_pcap.html). This method requires to load the entire
//! file to memory, and thus may not be good for large files.
//!
//! The [`PcapCapture`](../struct.PcapCapture.html) implements the
//! [`Capture`](../trait.Capture.html) trait to provide generic methods. However,
//! this trait also reads the entire file.
//!
//! The second method is to first parse the PCAP header
//! using [`parse_pcap_header`](fn.parse_pcap_header.html), then
//! loop over [`parse_pcap_frame`](fn.parse_pcap_frame.html) to get the data.
//! This can be used in a streaming parser.

use crate::error::PcapError;
use crate::linktype::Linktype;
use crate::utils::wrap_partial;
use winnow::{stream::AsBytes, IResult};

/// PCAP global header
#[derive(Clone, Debug)]
pub struct PcapHeader {
    /// File format and byte ordering. If equal to `0xa1b2c3d4` or `0xa1b23c4d` then the rest of
    /// the file uses native byte ordering. If `0xd4c3b2a1` or `0x4d3cb2a1` (swapped), then all
    /// following fields will have to be swapped too.
    pub magic_number: u32,
    /// Version major number (currently 2)
    pub version_major: u16,
    /// Version minor number (currently 4)
    pub version_minor: u16,
    /// The correction time in seconds between GMT (UTC) and the local timezone of the following packet header timestamps
    pub thiszone: i32,
    /// In theory, the accuracy of time stamps in the capture; in practice, all tools set it to 0
    pub sigfigs: u32,
    /// max len of captured packets, in octets
    pub snaplen: u32,
    /// Data link type
    pub network: Linktype,
}

impl PcapHeader {
    pub fn new() -> PcapHeader {
        PcapHeader {
            magic_number: 0xa1b2_c3d4, // native order
            version_major: 2,
            version_minor: 4,
            thiszone: 0,
            sigfigs: 0,
            snaplen: 0,
            network: Linktype(1), // default: LINKTYPE_ETHERNET
        }
    }

    pub const fn size(&self) -> usize {
        24
    }

    pub fn is_bigendian(&self) -> bool {
        (self.magic_number & 0xFFFF) == 0xb2a1 // works for both nanosecond and microsecond resolution timestamps
    }

    pub fn is_nanosecond_precision(&self) -> bool {
        self.magic_number == 0xa1b2_3c4d || self.magic_number == 0x4d3c_b2a1
    }
}

impl Default for PcapHeader {
    fn default() -> Self {
        PcapHeader::new()
    }
}

/// Container for network data in legacy Pcap files
#[derive(Debug)]
pub struct LegacyPcapBlock<I: AsBytes> {
    pub ts_sec: u32,
    pub ts_usec: u32,
    pub caplen: u32,
    pub origlen: u32,
    pub data: I,
}

pub mod generic {
    use winnow::bytes::take;
    use winnow::error::{ErrMode, Needed};
    use winnow::number::{be_i32, be_u16, be_u32, le_i32, le_u16, le_u32};
    use winnow::stream::{AsBytes, Stream, StreamIsPartial};
    use winnow::IResult;

    use crate::{Input, LegacyPcapBlock, Linktype, PcapError, PcapHeader};

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
    pub fn parse_pcap_frame_u8(
        i: Input,
    ) -> IResult<Input, LegacyPcapBlock<&[u8]>, PcapError<Input>> {
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
}

/// Read a PCAP record header and data
///
/// Each PCAP record starts with a small header, and is followed by packet data.
/// The packet data format depends on the LinkType.
///
/// This function wraps argument with `Partial` before calling [generic::parse_pcap_frame]
#[inline]
pub fn parse_pcap_frame(i: &[u8]) -> IResult<&[u8], LegacyPcapBlock<&[u8]>, PcapError<&[u8]>> {
    wrap_partial(generic::parse_pcap_frame)(i)
}

/// Read a PCAP record header and data (big-endian)
///
/// Each PCAP record starts with a small header, and is followed by packet data.
/// The packet data format depends on the LinkType.
///
/// This function wraps argument with `Partial` before calling [generic::parse_pcap_frame_be]
#[inline]
pub fn parse_pcap_frame_be(i: &[u8]) -> IResult<&[u8], LegacyPcapBlock<&[u8]>, PcapError<&[u8]>> {
    wrap_partial(generic::parse_pcap_frame_be)(i)
}

/// Read the PCAP global header
///
/// The global header contains the PCAP description and options
///
/// This function wraps argument with `Partial` before calling [generic::parse_pcap_header]
#[inline]
pub fn parse_pcap_header(i: &[u8]) -> IResult<&[u8], PcapHeader, PcapError<&[u8]>> {
    wrap_partial(generic::parse_pcap_header)(i)
}

#[cfg(test)]
pub mod tests {
    use crate::pcap::{parse_pcap_frame, parse_pcap_header};
    use crate::traits::tests::FRAME_PCAP;
    use hex_literal::hex;
    // ntp.pcap header
    pub const PCAP_HDR: &[u8] = &hex!(
        "
D4 C3 B2 A1 02 00 04 00 00 00 00 00 00 00 00 00
00 00 04 00 01 00 00 00"
    );

    // pcap header with nanosecond-precision timestamping
    pub const PCAP_HDR_NSEC: &[u8] = &hex!(
        "
4D 3C B2 A1 02 00 04 00 00 00 00 00 00 00 00 00
00 00 04 00 01 00 00 00"
    );
    #[test]
    fn test_parse_pcap_header() {
        let (rem, hdr) = parse_pcap_header(PCAP_HDR).expect("header parsing failed");
        assert!(rem.is_empty());
        assert_eq!(hdr.magic_number, 0xa1b2_c3d4);
        assert_eq!(hdr.version_major, 2);
        assert_eq!(hdr.version_minor, 4);
        assert_eq!(hdr.snaplen, 262_144);
        assert!(!hdr.is_nanosecond_precision());
    }
    #[test]
    fn test_parse_nanosecond_precision_pcap_header() {
        let (rem, hdr) = parse_pcap_header(PCAP_HDR_NSEC).expect("header parsing failed");
        assert!(rem.is_empty());
        assert_eq!(hdr.magic_number, 0xa1b2_3c4d);
        assert_eq!(hdr.version_major, 2);
        assert_eq!(hdr.version_minor, 4);
        assert_eq!(hdr.snaplen, 262_144);
        assert!(hdr.is_nanosecond_precision());
    }
    #[test]
    fn test_parse_pcap_frame() {
        let (rem, pkt) = parse_pcap_frame(FRAME_PCAP).expect("packet parsing failed");
        assert!(rem.is_empty());
        assert_eq!(pkt.origlen, 74);
        assert_eq!(pkt.ts_usec, 562_913);
        assert_eq!(pkt.ts_sec, 1_515_933_236);
    }
}
