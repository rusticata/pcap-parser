use nom::error::{ErrorKind, ParseError};
use nom::{Err, IResult};

use crate::endianness::{PcapBE, PcapEndianness, PcapLE};
use crate::{PcapError, CB_MAGIC, DCB_MAGIC};

use super::*;

#[derive(Debug)]
pub struct CustomBlock<'a> {
    pub block_type: u32,
    pub block_len1: u32,
    // Private Enterprise Number (PEN)
    pub pen: u32,
    pub data: &'a [u8],
    // pub options: &'a [u8],
    pub block_len2: u32,
}

impl<'a, En: PcapEndianness> PcapNGBlockParser<'a, En, CustomBlock<'a>> for CustomBlock<'a> {
    const HDR_SZ: usize = 16;
    const MAGIC: u32 = CB_MAGIC;

    fn inner_parse<E: ParseError<&'a [u8]>>(
        block_type: u32,
        block_len1: u32,
        i: &'a [u8],
        block_len2: u32,
    ) -> IResult<&'a [u8], CustomBlock<'a>, E> {
        // caller function already tested header type(magic) and length
        // read end of header
        let (i, pen) = En::parse_u32(i)?;
        // there is no way to differentiate custom data and options,
        // since length of data is not provided
        let data = i;
        if block_len2 != block_len1 {
            return Err(Err::Error(E::from_error_kind(i, ErrorKind::Verify)));
        }
        let block = CustomBlock {
            block_type,
            block_len1,
            pen,
            data,
            block_len2,
        };
        Ok((i, block))
    }
}

struct DCBParser;
impl<'a, En: PcapEndianness> PcapNGBlockParser<'a, En, CustomBlock<'a>> for DCBParser {
    const HDR_SZ: usize = 16;
    const MAGIC: u32 = DCB_MAGIC;

    fn inner_parse<E: ParseError<&'a [u8]>>(
        block_type: u32,
        block_len1: u32,
        i: &'a [u8],
        block_len2: u32,
    ) -> IResult<&'a [u8], CustomBlock<'a>, E> {
        <CustomBlock as PcapNGBlockParser<En, CustomBlock<'a>>>::inner_parse::<E>(
            block_type, block_len1, i, block_len2,
        )
    }
}

impl<'a> CustomBlock<'a> {
    pub fn do_not_copy(&self) -> bool {
        self.block_type == DCB_MAGIC || self.block_type == DCB_MAGIC.swap_bytes()
    }
}

/// Parse a Custom Block (little-endian)
#[inline]
pub fn parse_customblock_le(i: &[u8]) -> IResult<&[u8], CustomBlock, PcapError<&[u8]>> {
    ng_block_parser::<CustomBlock, PcapLE, _, _>()(i)
}

/// Parse a Custom Block (big-endian)
#[inline]
pub fn parse_customblock_be(i: &[u8]) -> IResult<&[u8], CustomBlock, PcapError<&[u8]>> {
    ng_block_parser::<CustomBlock, PcapBE, _, _>()(i)
}

/// Parse a Do-not-copy Custom Block (little-endian)
#[inline]
pub fn parse_dcb_le(i: &[u8]) -> IResult<&[u8], CustomBlock, PcapError<&[u8]>> {
    ng_block_parser::<DCBParser, PcapLE, _, _>()(i)
}

/// Parse a Do-not-copy Custom Block (big-endian)
#[inline]
pub fn parse_dcb_be(i: &[u8]) -> IResult<&[u8], CustomBlock, PcapError<&[u8]>> {
    ng_block_parser::<DCBParser, PcapBE, _, _>()(i)
}
