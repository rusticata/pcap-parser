use winnow::stream::AsBytes;

use super::pcap::{LegacyPcapBlock, PcapHeader};
use super::pcap_ng::Block;

/// A block from a Pcap or PcapNG file
pub enum PcapBlockOwned<I: AsBytes> {
    Legacy(LegacyPcapBlock<I>),
    LegacyHeader(PcapHeader),
    NG(Block<I>),
}

/// A block reference from a Pcap or PcapNG file
pub enum PcapBlock<'a, I: AsBytes> {
    Legacy(&'a LegacyPcapBlock<I>),
    LegacyHeader(&'a PcapHeader),
    NG(&'a Block<I>),
}

impl<I: AsBytes> From<LegacyPcapBlock<I>> for PcapBlockOwned<I> {
    fn from(b: LegacyPcapBlock<I>) -> PcapBlockOwned<I> {
        PcapBlockOwned::Legacy(b)
    }
}

impl<I: AsBytes> From<PcapHeader> for PcapBlockOwned<I> {
    fn from(b: PcapHeader) -> PcapBlockOwned<I> {
        PcapBlockOwned::LegacyHeader(b)
    }
}

impl<I: AsBytes> From<Block<I>> for PcapBlockOwned<I> {
    fn from(b: Block<I>) -> PcapBlockOwned<I> {
        PcapBlockOwned::NG(b)
    }
}

impl<'a, I: AsBytes> From<&'a LegacyPcapBlock<I>> for PcapBlock<'a, I> {
    fn from(b: &'a LegacyPcapBlock<I>) -> PcapBlock<'a, I> {
        PcapBlock::Legacy(b)
    }
}

impl<'a, I: AsBytes> From<&'a PcapHeader> for PcapBlock<'a, I> {
    fn from(b: &'a PcapHeader) -> PcapBlock<'a, I> {
        PcapBlock::LegacyHeader(b)
    }
}

impl<'a, I: AsBytes> From<&'a Block<I>> for PcapBlock<'a, I> {
    fn from(b: &'a Block<I>) -> PcapBlock<'a, I> {
        PcapBlock::NG(b)
    }
}
