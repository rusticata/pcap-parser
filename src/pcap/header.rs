use nom::number::streaming::{be_i32, be_u16, be_u32, le_i32, le_u16, le_u32};
use nom::IResult;

use crate::linktype::Linktype;
use crate::PcapError;

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

    pub fn is_modified_format(&self) -> bool {
        self.magic_number == 0xa1b2_cd34
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

/// Read the PCAP global header
///
/// The global header contains the PCAP description and options
pub fn parse_pcap_header(i: &[u8]) -> IResult<&[u8], PcapHeader, PcapError<&[u8]>> {
    let (i, magic_number) = le_u32(i)?;
    match magic_number {
        0xa1b2_c3d4 | 0xa1b2_3c4d | 0xa1b2_cd34 => {
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
        _ => Err(nom::Err::Error(PcapError::HeaderNotRecognized)),
    }
}
