use winnow::{
    error::{ErrMode, ErrorKind, ParseError},
    stream::{AsBytes, Stream, StreamIsPartial},
    IResult, Parser,
};

use super::blockparser::{ng_block_parser, PcapNGBlockParser};
use super::{opt_parse_options, PcapNGOption, ISB_MAGIC};
use crate::endianness::{PcapBE, PcapEndianness, PcapLE};
use crate::PcapError;

#[derive(Debug)]
pub struct InterfaceStatisticsBlock<I: AsBytes> {
    pub block_type: u32,
    pub block_len1: u32,
    pub if_id: u32,
    pub ts_high: u32,
    pub ts_low: u32,
    pub options: Vec<PcapNGOption<I>>,
    pub block_len2: u32,
}

impl<Input, En: PcapEndianness> PcapNGBlockParser<Input, En>
    for InterfaceStatisticsBlock<Input::Slice>
where
    Input: Stream<Token = u8, Slice = Input> + StreamIsPartial,
    <Input as Stream>::Slice: AsBytes,
{
    const HDR_SZ: usize = 24;
    const MAGIC: u32 = ISB_MAGIC;

    type Output = InterfaceStatisticsBlock<Input::Slice>;

    fn inner_parse<E: ParseError<Input>>(
        block_type: u32,
        block_len1: u32,
        i: Input,
        block_len2: u32,
    ) -> IResult<Input, Self::Output, E> {
        // caller function already tested header type(magic) and length
        // read end of header
        let (i, if_id) = En::parse_u32_gen(i)?;
        let (i, ts_high) = En::parse_u32_gen(i)?;
        let (i, ts_low) = En::parse_u32_gen(i)?;
        // caller function already tested header type(magic) and length
        // read options
        let (i, options) = opt_parse_options::<_, En, E>(i, block_len1 as usize, 24)?;
        if block_len2 != block_len1 {
            return Err(ErrMode::Backtrack(E::from_error_kind(i, ErrorKind::Verify)));
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

/// Parse an Interface Statistics Block (little-endian)
pub fn parse_interfacestatisticsblock_le<I>(
    i: I,
) -> IResult<I, InterfaceStatisticsBlock<I>, PcapError<I>>
where
    I: Stream<Token = u8, Slice = I> + StreamIsPartial,
    <I as Stream>::Slice: AsBytes,
{
    ng_block_parser::<I, InterfaceStatisticsBlock<_>, PcapLE, _, _>().parse_next(i)
}

/// Parse an Interface Statistics Block (big-endian)
pub fn parse_interfacestatisticsblock_be<I>(
    i: I,
) -> IResult<I, InterfaceStatisticsBlock<I>, PcapError<I>>
where
    I: Stream<Token = u8, Slice = I> + StreamIsPartial,
    <I as Stream>::Slice: AsBytes,
{
    ng_block_parser::<I, InterfaceStatisticsBlock<_>, PcapBE, _, _>().parse_next(i)
}
