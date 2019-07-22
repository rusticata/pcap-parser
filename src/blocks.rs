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
