use nom::error::ParseError;
use nom::IResult;

use crate::endianness::{PcapBE, PcapEndianness, PcapLE};
use crate::{PcapError, SJE_MAGIC};

use super::*;

#[derive(Debug)]
pub struct SystemdJournalExportBlock<'a> {
    pub block_type: u32,
    pub block_len1: u32,
    pub data: &'a [u8],
    pub block_len2: u32,
}

impl<'a, En: PcapEndianness> PcapNGBlockParser<'a, En, SystemdJournalExportBlock<'a>>
    for SystemdJournalExportBlock<'a>
{
    const HDR_SZ: usize = 12;
    const MAGIC: u32 = SJE_MAGIC;

    fn inner_parse<E: ParseError<&'a [u8]>>(
        block_type: u32,
        block_len1: u32,
        i: &'a [u8],
        block_len2: u32,
    ) -> IResult<&'a [u8], SystemdJournalExportBlock<'a>, E> {
        let block = SystemdJournalExportBlock {
            block_type,
            block_len1,
            data: i,
            block_len2,
        };
        Ok((i, block))
    }
}

/// Parse a SystemdJournalExport Block (little-endian)
#[inline]
pub fn parse_systemdjournalexportblock_le(
    i: &[u8],
) -> IResult<&[u8], SystemdJournalExportBlock, PcapError<&[u8]>> {
    ng_block_parser::<SystemdJournalExportBlock, PcapLE, _, _>()(i)
}

/// Parse a SystemdJournalExport Block (big-endian)
#[inline]
pub fn parse_systemdjournalexportblock_be(
    i: &[u8],
) -> IResult<&[u8], SystemdJournalExportBlock, PcapError<&[u8]>> {
    ng_block_parser::<SystemdJournalExportBlock, PcapBE, _, _>()(i)
}
