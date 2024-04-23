use nom::error::ParseError;
use nom::number::streaming::{be_i64, be_u16, le_i64, le_u16, le_u32};
use nom::{Err, IResult};

use crate::endianness::{PcapBE, PcapLE};
use crate::utils::array_ref4;
use crate::{opt_parse_options, PcapError, PcapNGOption, SHB_MAGIC};

use super::*;

/// The Section Header Block (SHB) identifies the
/// beginning of a section of the capture capture file.
///
/// The
/// Section Header Block does not contain data but it rather identifies a
/// list of blocks (interfaces, packets) that are logically correlated.
#[derive(Debug)]
pub struct SectionHeaderBlock<'a> {
    pub block_type: u32,
    pub block_len1: u32,
    /// Byte-order magic
    pub bom: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub section_len: i64,
    pub options: Vec<PcapNGOption<'a>>,
    pub block_len2: u32,
}

impl<'a> SectionHeaderBlock<'a> {
    pub fn big_endian(&self) -> bool {
        self.bom != BOM_MAGIC
    }
}

impl<'a> PcapNGBlockParser<'a, PcapBE, SectionHeaderBlock<'a>> for SectionHeaderBlock<'a> {
    const HDR_SZ: usize = 28;
    const MAGIC: u32 = SHB_MAGIC;

    fn inner_parse<E: ParseError<&'a [u8]>>(
        block_type: u32,
        block_len1: u32,
        i: &'a [u8],
        block_len2: u32,
    ) -> IResult<&'a [u8], SectionHeaderBlock<'a>, E> {
        // caller function already tested header type(magic) and length
        // read end of header
        let (i, bom) = le_u32(i)?;
        let (i, major_version) = be_u16(i)?;
        let (i, minor_version) = be_u16(i)?;
        let (i, section_len) = be_i64(i)?;
        let (i, options) = opt_parse_options::<PcapBE, E>(i, block_len1 as usize, 28)?;
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

impl<'a> PcapNGBlockParser<'a, PcapLE, SectionHeaderBlock<'a>> for SectionHeaderBlock<'a> {
    const HDR_SZ: usize = 28;
    const MAGIC: u32 = SHB_MAGIC;

    fn inner_parse<E: ParseError<&'a [u8]>>(
        block_type: u32,
        block_len1: u32,
        i: &'a [u8],
        block_len2: u32,
    ) -> IResult<&'a [u8], SectionHeaderBlock<'a>, E> {
        // caller function already tested header type(magic) and length
        // read end of header
        let (i, bom) = le_u32(i)?;
        let (i, major_version) = le_u16(i)?;
        let (i, minor_version) = le_u16(i)?;
        let (i, section_len) = le_i64(i)?;
        let (i, options) = opt_parse_options::<PcapLE, E>(i, block_len1 as usize, 28)?;
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

/// Parse a Section Header Block (little endian)
pub fn parse_sectionheaderblock_le(
    i: &[u8],
) -> IResult<&[u8], SectionHeaderBlock, PcapError<&[u8]>> {
    ng_block_parser::<SectionHeaderBlock, PcapLE, _, _>()(i)
}

/// Parse a Section Header Block (big endian)
pub fn parse_sectionheaderblock_be(
    i: &[u8],
) -> IResult<&[u8], SectionHeaderBlock, PcapError<&[u8]>> {
    ng_block_parser::<SectionHeaderBlock, PcapBE, _, _>()(i)
}

/// Parse a SectionHeaderBlock (little or big endian)
pub fn parse_sectionheaderblock(i: &[u8]) -> IResult<&[u8], SectionHeaderBlock, PcapError<&[u8]>> {
    if i.len() < 12 {
        return Err(Err::Incomplete(nom::Needed::new(12 - i.len())));
    }
    let bom = u32::from_le_bytes(*array_ref4(i, 8));
    if bom == BOM_MAGIC {
        parse_sectionheaderblock_le(i)
    } else if bom == u32::from_be(BOM_MAGIC) {
        parse_sectionheaderblock_be(i)
    } else {
        Err(Err::Error(PcapError::HeaderNotRecognized))
    }
}
