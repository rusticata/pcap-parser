use winnow::stream::AsBytes;

use crate::Linktype;

pub mod parser;

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
