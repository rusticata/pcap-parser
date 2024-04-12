use winnow::{
    error::ParseError,
    stream::{AsBytes, Stream, StreamIsPartial},
    IResult, Parser,
};

use super::blockparser::{ng_block_parser, PcapNGBlockParser};
use crate::{
    endianness::{PcapBE, PcapEndianness, PcapLE},
    PcapError,
};

/// Unknown block (magic not recognized, or not yet implemented)
#[derive(Debug)]
pub struct UnknownBlock<I: AsBytes> {
    /// Block type (little endian)
    pub block_type: u32,
    pub block_len1: u32,
    pub data: I,
    pub block_len2: u32,
}

impl<Input, En: PcapEndianness> PcapNGBlockParser<Input, En> for UnknownBlock<Input::Slice>
where
    Input: Stream<Token = u8, Slice = Input> + StreamIsPartial,
    <Input as Stream>::Slice: AsBytes,
{
    const HDR_SZ: usize = 12;
    const MAGIC: u32 = 0;

    type Output = UnknownBlock<Input::Slice>;

    fn inner_parse<E: ParseError<Input>>(
        block_type: u32,
        block_len1: u32,
        i: Input,
        block_len2: u32,
    ) -> IResult<Input, Self::Output, E> {
        let block = UnknownBlock {
            block_type,
            block_len1,
            data: i.clone(),
            block_len2,
        };
        Ok((i, block))
    }
}

/// Parse an unknown block (little-endian)
pub fn parse_unknownblock_le<I>(i: I) -> IResult<I, UnknownBlock<I>, PcapError<I>>
where
    I: Stream<Token = u8, Slice = I> + StreamIsPartial,
    <I as Stream>::Slice: AsBytes,
{
    ng_block_parser::<I, UnknownBlock<_>, PcapLE, _, _>().parse_next(i)
}

/// Parse an unknown block (big-endian)
pub fn parse_unknownblock_be<I>(i: I) -> IResult<I, UnknownBlock<I>, PcapError<I>>
where
    I: Stream<Token = u8, Slice = I> + StreamIsPartial,
    <I as Stream>::Slice: AsBytes,
{
    ng_block_parser::<I, UnknownBlock<_>, PcapBE, _, _>().parse_next(i)
}
