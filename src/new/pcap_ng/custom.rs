use winnow::{
    bytes::take,
    error::{ErrMode, ErrorKind, ParseError},
    stream::{AsBytes, Stream, StreamIsPartial},
    IResult, Parser,
};

use super::blockparser::{ng_block_parser, PcapNGBlockParser};
use super::{CB_MAGIC, DCB_MAGIC};
use crate::endianness::{PcapBE, PcapEndianness, PcapLE};
use crate::PcapError;

#[derive(Debug)]
pub struct CustomBlock<I: AsBytes> {
    pub block_type: u32,
    pub block_len1: u32,
    // Private Enterprise Number (PEN)
    pub pen: u32,
    pub data: I,
    // pub options: &'a [u8],
    pub block_len2: u32,
}

impl<Input, En: PcapEndianness> PcapNGBlockParser<Input, En> for CustomBlock<Input::Slice>
where
    Input: Stream<Token = u8, Slice = Input> + StreamIsPartial,
    <Input as Stream>::Slice: AsBytes,
{
    const HDR_SZ: usize = 16;
    const MAGIC: u32 = CB_MAGIC;

    type Output = CustomBlock<Input::Slice>;

    fn inner_parse<E: ParseError<Input>>(
        block_type: u32,
        block_len1: u32,
        i: Input,
        block_len2: u32,
    ) -> IResult<Input, Self::Output, E> {
        // caller function already tested header type(magic) and length
        // read end of header
        let (i, pen) = En::parse_u32_gen(i)?;
        // there is no way to differentiate custom data and options,
        // since length of data is not provided
        let (rem, data) = take(i.eof_offset()).parse_next(i)?;
        if block_len2 != block_len1 {
            return Err(ErrMode::Backtrack(E::from_error_kind(
                data,
                ErrorKind::Verify,
            )));
        }
        let block = CustomBlock {
            block_type,
            block_len1,
            pen,
            data,
            block_len2,
        };
        Ok((rem, block))
    }
}

struct DCBParser;
impl<Input, En: PcapEndianness> PcapNGBlockParser<Input, En> for DCBParser
where
    Input: Stream<Token = u8, Slice = Input> + StreamIsPartial,
    <Input as Stream>::Slice: AsBytes,
{
    const HDR_SZ: usize = 16;
    const MAGIC: u32 = DCB_MAGIC;

    type Output = CustomBlock<Input::Slice>;

    fn inner_parse<E: ParseError<Input>>(
        block_type: u32,
        block_len1: u32,
        i: Input,
        block_len2: u32,
    ) -> IResult<Input, Self::Output, E> {
        <CustomBlock<Input> as PcapNGBlockParser<Input, En>>::inner_parse::<E>(
            block_type, block_len1, i, block_len2,
        )
    }
}

impl<I: AsBytes> CustomBlock<I> {
    pub fn do_not_copy(&self) -> bool {
        self.block_type == DCB_MAGIC || self.block_type == DCB_MAGIC.swap_bytes()
    }
}

/// Parse a Custom Block (little-endian)
pub fn parse_customblock_le<I>(i: I) -> IResult<I, CustomBlock<I>, PcapError<I>>
where
    I: Stream<Token = u8, Slice = I> + StreamIsPartial,
    <I as Stream>::Slice: AsBytes,
{
    ng_block_parser::<I, CustomBlock<_>, PcapLE, _, _>().parse_next(i)
}

/// Parse a Custom Block (big-endian)
pub fn parse_customblock_be<I>(i: I) -> IResult<I, CustomBlock<I>, PcapError<I>>
where
    I: Stream<Token = u8, Slice = I> + StreamIsPartial,
    <I as Stream>::Slice: AsBytes,
{
    ng_block_parser::<I, CustomBlock<_>, PcapBE, _, _>().parse_next(i)
}

/// Parse a Do-not-copy Custom Block (little-endian)
pub fn parse_dcb_le<I>(i: I) -> IResult<I, CustomBlock<I>, PcapError<I>>
where
    I: Stream<Token = u8, Slice = I> + StreamIsPartial,
    <I as Stream>::Slice: AsBytes,
{
    ng_block_parser::<I, DCBParser, PcapLE, _, _>().parse_next(i)
}

/// Parse a Do-not-copy Custom Block (big-endian)
pub fn parse_dcb_be<I>(i: I) -> IResult<I, CustomBlock<I>, PcapError<I>>
where
    I: Stream<Token = u8, Slice = I> + StreamIsPartial,
    <I as Stream>::Slice: AsBytes,
{
    ng_block_parser::<I, DCBParser, PcapBE, _, _>().parse_next(i)
}
