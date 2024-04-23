use nom::bytes::streaming::take;
use nom::error::ParseError;
use nom::IResult;

use crate::endianness::{PcapBE, PcapEndianness, PcapLE};
use crate::traits::PcapNGPacketBlock;
use crate::{PcapError, SPB_MAGIC};

use super::*;

/// The Simple Packet Block (SPB) is a lightweight container for storing
/// the packets coming from the network.
///
/// This struct is a thin abstraction layer, and stores the raw block data.
/// For ex the `data` field is stored with the padding.
/// It implements the `PcapNGPacketBlock` trait, which provides helper functions.
#[derive(Debug)]
pub struct SimplePacketBlock<'a> {
    /// Block type (little endian)
    pub block_type: u32,
    pub block_len1: u32,
    /// Original packet length
    pub origlen: u32,
    pub data: &'a [u8],
    pub block_len2: u32,
}

impl<'a> PcapNGPacketBlock for SimplePacketBlock<'a> {
    fn big_endian(&self) -> bool {
        self.block_type != SPB_MAGIC
    }
    fn truncated(&self) -> bool {
        self.origlen as usize <= self.data.len()
    }
    fn orig_len(&self) -> u32 {
        self.origlen
    }
    fn raw_packet_data(&self) -> &[u8] {
        self.data
    }
    fn packet_data(&self) -> &[u8] {
        let caplen = self.origlen as usize;
        if caplen < self.data.len() {
            &self.data[..caplen]
        } else {
            self.data
        }
    }
}

impl<'a, En: PcapEndianness> PcapNGBlockParser<'a, En, SimplePacketBlock<'a>>
    for SimplePacketBlock<'a>
{
    const HDR_SZ: usize = 16;
    const MAGIC: u32 = SPB_MAGIC;

    fn inner_parse<E: ParseError<&'a [u8]>>(
        block_type: u32,
        block_len1: u32,
        i: &'a [u8],
        block_len2: u32,
    ) -> IResult<&'a [u8], SimplePacketBlock<'a>, E> {
        // caller function already tested header type(magic) and length
        // read end of header
        let (i, origlen) = En::parse_u32(i)?;
        let (i, data) = take((block_len1 as usize) - 16)(i)?;
        let block = SimplePacketBlock {
            block_type,
            block_len1,
            origlen,
            data,
            block_len2,
        };
        Ok((i, block))
    }
}

/// Parse a Simple Packet Block (little-endian)
///
/// *Note: this function does not remove padding in the `data` field.
/// Use `packet_data` to get field without padding.*
pub fn parse_simplepacketblock_le(i: &[u8]) -> IResult<&[u8], SimplePacketBlock, PcapError<&[u8]>> {
    ng_block_parser::<SimplePacketBlock, PcapLE, _, _>()(i)
}

/// Parse a Simple Packet Block (big-endian)
///
/// *Note: this function does not remove padding*
pub fn parse_simplepacketblock_be(i: &[u8]) -> IResult<&[u8], SimplePacketBlock, PcapError<&[u8]>> {
    ng_block_parser::<SimplePacketBlock, PcapBE, _, _>()(i)
}
