use nom::error::ParseError;
use nom::IResult;

use crate::endianness::{PcapBE, PcapEndianness, PcapLE};
use crate::PcapError;

use super::*;

/// Unknown block (magic not recognized, or not yet implemented)
#[derive(Debug)]
pub struct UnknownBlock<'a> {
    /// Block type (little endian)
    pub block_type: u32,
    pub block_len1: u32,
    pub data: &'a [u8],
    pub block_len2: u32,
}

impl<'a, En: PcapEndianness> PcapNGBlockParser<'a, En, UnknownBlock<'a>> for UnknownBlock<'a> {
    const HDR_SZ: usize = 12;
    const MAGIC: u32 = 0;

    fn inner_parse<E: ParseError<&'a [u8]>>(
        block_type: u32,
        block_len1: u32,
        i: &'a [u8],
        block_len2: u32,
    ) -> IResult<&'a [u8], UnknownBlock<'a>, E> {
        let block = UnknownBlock {
            block_type,
            block_len1,
            data: i,
            block_len2,
        };
        Ok((i, block))
    }
}

/// Parse an unknown block (little-endian)
pub fn parse_unknownblock_le(i: &[u8]) -> IResult<&[u8], UnknownBlock, PcapError<&[u8]>> {
    ng_block_parser::<UnknownBlock, PcapLE, _, _>()(i)
}

/// Parse an unknown block (big-endian)
pub fn parse_unknownblock_be(i: &[u8]) -> IResult<&[u8], UnknownBlock, PcapError<&[u8]>> {
    ng_block_parser::<UnknownBlock, PcapBE, _, _>()(i)
}
