use crate::pcapng::Block;
use crate::traits::*;
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
