use crate::pcap::{LegacyPcapBlock, PcapHeader};
use crate::pcapng::Block;

/// A block from a Pcap or PcapNG file
pub enum PcapBlockOwned<'a> {
    Legacy(LegacyPcapBlock<&'a [u8]>),
    LegacyHeader(PcapHeader),
    NG(Block<'a>),
}

/// A block from a Pcap or PcapNG file
pub enum PcapBlock<'a> {
    Legacy(&'a LegacyPcapBlock<&'a [u8]>),
    LegacyHeader(&'a PcapHeader),
    NG(&'a Block<'a>),
}

impl<'a> From<LegacyPcapBlock<&'a [u8]>> for PcapBlockOwned<'a> {
    fn from(b: LegacyPcapBlock<&'a [u8]>) -> PcapBlockOwned<'a> {
        PcapBlockOwned::Legacy(b)
    }
}

impl<'a> From<PcapHeader> for PcapBlockOwned<'a> {
    fn from(b: PcapHeader) -> PcapBlockOwned<'a> {
        PcapBlockOwned::LegacyHeader(b)
    }
}

impl<'a> From<Block<'a>> for PcapBlockOwned<'a> {
    fn from(b: Block<'a>) -> PcapBlockOwned<'a> {
        PcapBlockOwned::NG(b)
    }
}

impl<'a, 'b> From<&'a LegacyPcapBlock<&'b [u8]>> for PcapBlock<'a> {
    fn from(b: &'a LegacyPcapBlock<&'b [u8]>) -> PcapBlock<'a> {
        PcapBlock::Legacy(b)
    }
}

impl<'a> From<&'a PcapHeader> for PcapBlock<'a> {
    fn from(b: &'a PcapHeader) -> PcapBlock<'a> {
        PcapBlock::LegacyHeader(b)
    }
}

impl<'a> From<&'a Block<'a>> for PcapBlock<'a> {
    fn from(b: &'a Block) -> PcapBlock<'a> {
        PcapBlock::NG(b)
    }
}
