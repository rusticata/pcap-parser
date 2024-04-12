use winnow::error::ParseError;
use winnow::number::le_u32;
use winnow::stream::{AsBytes, Stream, StreamIsPartial};
use winnow::{IResult, Parser};

use crate::endianness::{PcapBE, PcapEndianness, PcapLE};
use crate::PcapError;

use super::blockparser::{ng_block_parser, PcapNGBlockParser};
use super::{opt_parse_options, PcapNGOption, BOM_MAGIC, SHB_MAGIC};

/// The Section Header Block (SHB) identifies the
/// beginning of a section of the capture capture file.
///
/// The
/// Section Header Block does not contain data but it rather identifies a
/// list of blocks (interfaces, packets) that are logically correlated.
#[derive(Debug)]
pub struct SectionHeaderBlock<B: AsBytes> {
    pub block_type: u32,
    pub block_len1: u32,
    /// Byte-order magic
    pub bom: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub section_len: i64,
    pub options: Vec<PcapNGOption<B>>,
    pub block_len2: u32,
}

impl<I: AsBytes> SectionHeaderBlock<I> {
    pub fn big_endian(&self) -> bool {
        self.bom != BOM_MAGIC
    }
}

impl<Input, En: PcapEndianness> PcapNGBlockParser<Input, En> for SectionHeaderBlock<Input::Slice>
where
    Input: Stream<Token = u8, Slice = Input> + StreamIsPartial,
    <Input as Stream>::Slice: AsBytes,
{
    const HDR_SZ: usize = 28;
    const MAGIC: u32 = SHB_MAGIC;

    type Output = SectionHeaderBlock<Input::Slice>;

    fn inner_parse<E: ParseError<Input>>(
        block_type: u32,
        block_len1: u32,
        i: Input,
        block_len2: u32,
    ) -> IResult<Input, Self::Output, E> {
        // caller function already tested header type(magic) and length
        // read end of header
        let (i, bom) = le_u32(i)?;
        let (i, major_version) = En::parse_u16_gen(i)?;
        let (i, minor_version) = En::parse_u16_gen(i)?;
        let (i, section_len) = En::parse_i64_gen(i)?;
        let (i, options) = opt_parse_options::<_, En, E>(i, block_len1 as usize, 28)?;
        let block = SectionHeaderBlock {
            block_type,
            block_len1,
            bom,
            major_version,
            minor_version,
            section_len,
            options,
            block_len2,
        };
        Ok((i, block))
    }
}

#[inline]
pub fn parse_sectionheaderblock_le<I>(i: I) -> IResult<I, SectionHeaderBlock<I>, PcapError<I>>
where
    I: Stream<Token = u8, Slice = I> + StreamIsPartial,
    <I as Stream>::Slice: AsBytes,
{
    ng_block_parser::<I, SectionHeaderBlock<_>, PcapLE, _, _>().parse_next(i)
}

#[inline]
pub fn parse_sectionheaderblock_be<I>(i: I) -> IResult<I, SectionHeaderBlock<I>, PcapError<I>>
where
    I: Stream<Token = u8, Slice = I> + StreamIsPartial,
    <I as Stream>::Slice: AsBytes,
{
    ng_block_parser::<I, SectionHeaderBlock<_>, PcapBE, _, _>().parse_next(i)
}
