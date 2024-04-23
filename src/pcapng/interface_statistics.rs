use nom::error::{ErrorKind, ParseError};
use nom::{Err, IResult};

use crate::endianness::{PcapBE, PcapEndianness, PcapLE};
use crate::{opt_parse_options, PcapError, PcapNGOption, ISB_MAGIC};

use super::*;

#[derive(Debug)]
pub struct InterfaceStatisticsBlock<'a> {
    pub block_type: u32,
    pub block_len1: u32,
    pub if_id: u32,
    pub ts_high: u32,
    pub ts_low: u32,
    pub options: Vec<PcapNGOption<'a>>,
    pub block_len2: u32,
}

impl<'a, En: PcapEndianness> PcapNGBlockParser<'a, En, InterfaceStatisticsBlock<'a>>
    for InterfaceStatisticsBlock<'a>
{
    const HDR_SZ: usize = 24;
    const MAGIC: u32 = ISB_MAGIC;

    fn inner_parse<E: ParseError<&'a [u8]>>(
        block_type: u32,
        block_len1: u32,
        i: &'a [u8],
        block_len2: u32,
    ) -> IResult<&'a [u8], InterfaceStatisticsBlock<'a>, E> {
        // caller function already tested header type(magic) and length
        // read end of header
        let (i, if_id) = En::parse_u32(i)?;
        let (i, ts_high) = En::parse_u32(i)?;
        let (i, ts_low) = En::parse_u32(i)?;
        // caller function already tested header type(magic) and length
        // read options
        let (i, options) = opt_parse_options::<En, E>(i, block_len1 as usize, 24)?;
        if block_len2 != block_len1 {
            return Err(Err::Error(E::from_error_kind(i, ErrorKind::Verify)));
        }
        let block = InterfaceStatisticsBlock {
            block_type,
            block_len1,
            if_id,
            ts_high,
            ts_low,
            options,
            block_len2,
        };
        Ok((i, block))
    }
}

/// Parse an InterfaceStatistics Block (little-endian)
#[inline]
pub fn parse_interfacestatisticsblock_le(
    i: &[u8],
) -> IResult<&[u8], InterfaceStatisticsBlock, PcapError<&[u8]>> {
    ng_block_parser::<InterfaceStatisticsBlock, PcapLE, _, _>()(i)
}

/// Parse an InterfaceStatistics Block (big-endian)
#[inline]
pub fn parse_interfacestatisticsblock_be(
    i: &[u8],
) -> IResult<&[u8], InterfaceStatisticsBlock, PcapError<&[u8]>> {
    ng_block_parser::<InterfaceStatisticsBlock, PcapBE, _, _>()(i)
}
