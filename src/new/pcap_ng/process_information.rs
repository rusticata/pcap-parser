use winnow::{
    error::{ErrMode, ErrorKind, ParseError},
    stream::{AsBytes, Stream, StreamIsPartial},
    IResult, Parser,
};

use super::blockparser::{ng_block_parser, PcapNGBlockParser};
use super::{opt_parse_options, PcapNGOption, PIB_MAGIC};
use crate::endianness::{PcapBE, PcapEndianness, PcapLE};
use crate::PcapError;

#[derive(Debug)]
pub struct ProcessInformationBlock<I: AsBytes> {
    pub block_type: u32,
    pub block_len1: u32,
    pub process_id: u32,
    pub options: Vec<PcapNGOption<I>>,
    pub block_len2: u32,
}

impl<Input, En: PcapEndianness> PcapNGBlockParser<Input, En>
    for ProcessInformationBlock<Input::Slice>
where
    Input: Stream<Token = u8, Slice = Input> + StreamIsPartial,
    <Input as Stream>::Slice: AsBytes,
{
    const HDR_SZ: usize = 4;
    const MAGIC: u32 = PIB_MAGIC;

    type Output = ProcessInformationBlock<Input::Slice>;

    fn inner_parse<E: ParseError<Input>>(
        block_type: u32,
        block_len1: u32,
        i: Input,
        block_len2: u32,
    ) -> IResult<Input, Self::Output, E> {
        // caller function already tested header type(magic) and length
        // read options
        let (i, process_id) = En::parse_u32_gen(i)?;
        let (i, options) = opt_parse_options::<_, En, E>(i, (block_len1 - 4) as usize, 12)?;
        if block_len2 != block_len1 {
            return Err(ErrMode::Backtrack(E::from_error_kind(i, ErrorKind::Verify)));
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

/// Parse a Process Information Block (little-endian)
pub fn parse_processinformationblock_le<I>(
    i: I,
) -> IResult<I, ProcessInformationBlock<I>, PcapError<I>>
where
    I: Stream<Token = u8, Slice = I> + StreamIsPartial,
    <I as Stream>::Slice: AsBytes,
{
    ng_block_parser::<I, ProcessInformationBlock<_>, PcapLE, _, _>().parse_next(i)
}

/// Parse a Process Information Block (big-endian)
pub fn parse_processinformationblock_be<I>(
    i: I,
) -> IResult<I, ProcessInformationBlock<I>, PcapError<I>>
where
    I: Stream<Token = u8, Slice = I> + StreamIsPartial,
    <I as Stream>::Slice: AsBytes,
{
    ng_block_parser::<I, ProcessInformationBlock<_>, PcapBE, _, _>().parse_next(i)
}
