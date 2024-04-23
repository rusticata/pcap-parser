use nom::error::{ErrorKind, ParseError};
use nom::{Err, IResult};

use crate::endianness::{PcapBE, PcapEndianness, PcapLE};
use crate::{opt_parse_options, PcapError, PcapNGOption, PIB_MAGIC};

use super::*;

#[derive(Debug)]
pub struct ProcessInformationBlock<'a> {
    pub block_type: u32,
    pub block_len1: u32,
    pub process_id: u32,
    pub options: Vec<PcapNGOption<'a>>,
    pub block_len2: u32,
}

impl<'a, En: PcapEndianness> PcapNGBlockParser<'a, En, ProcessInformationBlock<'a>>
    for ProcessInformationBlock<'a>
{
    const MAGIC: u32 = PIB_MAGIC;
    const HDR_SZ: usize = 4;

    fn inner_parse<E: ParseError<&'a [u8]>>(
        block_type: u32,
        block_len1: u32,
        i: &'a [u8],
        block_len2: u32,
    ) -> IResult<&'a [u8], ProcessInformationBlock<'a>, E> {
        // caller function already tested header type(magic) and length
        // read options
        let (i, process_id) = En::parse_u32(i)?;
        let (i, options) = opt_parse_options::<En, E>(i, (block_len1 - 4) as usize, 12)?;
        if block_len2 != block_len1 {
            return Err(Err::Error(E::from_error_kind(i, ErrorKind::Verify)));
        }
        let block = ProcessInformationBlock {
            block_type,
            block_len1,
            process_id,
            options,
            block_len2,
        };
        Ok((i, block))
    }
}

/// Parse a ProcessInformation Block (little-endian)
#[inline]
pub fn parse_processinformationblock_le(
    i: &[u8],
) -> IResult<&[u8], ProcessInformationBlock, PcapError<&[u8]>> {
    ng_block_parser::<ProcessInformationBlock, PcapLE, _, _>()(i)
}

/// Parse a ProcessInformation Block (big-endian)
#[inline]
pub fn parse_processinformationblock_be(
    i: &[u8],
) -> IResult<&[u8], ProcessInformationBlock, PcapError<&[u8]>> {
    ng_block_parser::<ProcessInformationBlock, PcapBE, _, _>()(i)
}
