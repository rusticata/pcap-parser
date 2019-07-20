use crate::pcapng::Block;
use crate::traits::*;
use cookie_factory::GenError;
use std::convert::From;

/// A block from a Pcap or PcapNG file
pub enum PcapBlockOwned<'a> {
    Legacy(LegacyPcapBlock<'a>),
    NG(Block<'a>),
}

/// A block from a Pcap or PcapNG file
pub enum PcapBlock<'a> {
    Legacy(&'a LegacyPcapBlock<'a>),
    NG(&'a Block<'a>),
}

impl<'a> From<LegacyPcapBlock<'a>> for PcapBlockOwned<'a> {
    fn from(b: LegacyPcapBlock<'a>) -> PcapBlockOwned<'a> {
        PcapBlockOwned::Legacy(b)
    }
}

impl<'a> From<Block<'a>> for PcapBlockOwned<'a> {
    fn from(b: Block<'a>) -> PcapBlockOwned<'a> {
        PcapBlockOwned::NG(b)
    }
}

impl<'a> From<&'a LegacyPcapBlock<'a>> for PcapBlock<'a> {
    fn from(b: &'a LegacyPcapBlock) -> PcapBlock<'a> {
        PcapBlock::Legacy(b)
    }
}

impl<'a> From<&'a Block<'a>> for PcapBlock<'a> {
    fn from(b: &'a Block) -> PcapBlock<'a> {
        PcapBlock::NG(b)
    }
}

/// Packet data
///
/// The format of packet data depends on the
/// [`LinkType`](struct.Linktype.html) of the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet<'a> {
    /// The record header
    pub header: PacketHeader,
    /// The identifier of interface where the packet was captured
    pub interface: u32,
    /// Actual packet data
    pub data: &'a [u8],
}

/// Record (Packet) Header
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketHeader {
    /// The date and time when this packet was captured (seconds since epoch).
    pub ts_sec: u32,
    /// In regular pcap files, the microseconds when this packet was captured,
    /// as an offset to ts_sec. In nanosecond-resolution files, this is,
    /// instead, the nanoseconds when the packet was captured, as an offset to
    /// ts_sec
    pub ts_fractional: u32,
    /// Time resolution unit (in unit per seconds)
    pub ts_unit: u64,
    /// The number of bytes of packet data actually captured and saved in the
    /// file.
    pub caplen: u32,
    /// The length of the packet as it appeared on the network when it was
    /// captured.
    /// If `cap_len` and `len` differ, the actually saved packet size was
    /// limited by `snaplen`.
    pub len: u32,
}

impl PacketHeader {
    pub fn to_string(&self) -> Vec<u8> {
        let mut mem: [u8; 16] = [0; 16];

        let r = do_gen! {
            (&mut mem,0),
            gen_le_u32!(self.ts_sec) >>
            gen_le_u32!(self.ts_micros()) >>
            gen_le_u32!(self.caplen) >>
            gen_le_u32!(self.len)
        };
        match r {
            Ok((s, _)) => s.to_vec(),
            Err(e) => panic!("error {:?}", e),
        }
    }
    pub fn ts_sec(&self) -> u32 {
        self.ts_sec
    }
    pub fn ts_micros(&self) -> u32 {
        const MICROS_PER_SEC: u64 = 1_000_000;
        self.ts_fractional / ((self.ts_unit / MICROS_PER_SEC) as u32)
    }
}

/// Data link type
///
/// The link-layer header type specifies the type of headers at the beginning
/// of the packet.
///
/// See [http://www.tcpdump.org/linktypes.html](http://www.tcpdump.org/linktypes.html)
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Linktype(pub i32);

newtype_enum! {
impl display Linktype {
    NULL = 0,
    ETHERNET = 1,

    FDDI = 10,

    RAW = 101,

    LOOP = 108,
    LINUX_SLL = 113,

    // Raw IPv4; the packet begins with an IPv4 header.
    IPV4 = 228,
    // Raw IPv6; the packet begins with an IPv6 header.
    IPv6 = 229,

    // Linux netlink NETLINK NFLOG socket log messages.
    // Use the [`pcap_nflog`]()../pcap_nflog/index.html module to access content.
    NFLOG = 239,
}
}
