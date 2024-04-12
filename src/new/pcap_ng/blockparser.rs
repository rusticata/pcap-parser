use winnow::bytes::take;
use winnow::error::{ErrMode, ErrorKind, Needed, ParseError};
use winnow::number::le_u32;
use winnow::stream::{AsBytes, Stream, StreamIsPartial};
use winnow::{IResult, Parser};

use crate::endianness::PcapEndianness;

pub(crate) trait PcapNGBlockParser<Input, En: PcapEndianness>
where
    Input: Stream<Token = u8> + StreamIsPartial,
    <Input as Stream>::Slice: AsBytes,
{
    /// Minimum header size, in bytes
    const HDR_SZ: usize;
    /// Little-endian magic number for this block type
    const MAGIC: u32;

    type Output;

    // caller function must have tested header type(magic) and length
    fn inner_parse<E: ParseError<Input>>(
        block_type: u32,
        block_len1: u32,
        i: Input,
        block_len2: u32,
    ) -> IResult<Input, Self::Output, E>;
}

/// Create a block parser function, given the parameters (block object and endianness)
pub(crate) fn ng_block_parser<I, P, En, O, E>() -> impl Parser<I, O, E>
where
    I: Stream<Token = u8, Slice = I> + StreamIsPartial,
    <I as Stream>::Slice: AsBytes,
    P: PcapNGBlockParser<I, En, Output = O>,
    En: PcapEndianness,
    E: ParseError<I>,
{
    move |i: I| {
        // read generic block layout
        //
        if i.is_partial() && (i.eof_offset() < P::HDR_SZ) {
            return Err(ErrMode::Incomplete(Needed::new(P::HDR_SZ - i.eof_offset())));
        }
        let (i, block_type) = le_u32(i)?;
        let (i, block_len1) = En::parse_u32_gen(i)?;
        if block_len1 < P::HDR_SZ as u32 {
            return Err(ErrMode::Backtrack(E::from_error_kind(i, ErrorKind::Verify)));
        }
        if P::MAGIC != 0 && En::native_u32(block_type) != P::MAGIC {
            return Err(ErrMode::Backtrack(E::from_error_kind(i, ErrorKind::Verify)));
        }
        // 12 is block_type (4) + block_len1 (4) + block_len2 (4)
        let (i, block_content) = take(block_len1 - 12)(i)?;
        let (i, block_len2) = En::parse_u32_gen(i)?;
        // call block content parsing function
        let (_, b) = P::inner_parse(block_type, block_len1, block_content, block_len2)?;
        // return the remaining bytes from the container, not content
        Ok((i, b))
    }
}
