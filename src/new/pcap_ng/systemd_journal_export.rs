use winnow::{
    bytes::take,
    error::ParseError,
    stream::{AsBytes, Stream, StreamIsPartial},
    IResult, Parser,
};

use super::blockparser::{ng_block_parser, PcapNGBlockParser};
use super::SJE_MAGIC;
use crate::endianness::{PcapBE, PcapEndianness, PcapLE};
use crate::PcapError;

#[derive(Debug)]
pub struct SystemdJournalExportBlock<I: AsBytes> {
    pub block_type: u32,
    pub block_len1: u32,
    pub data: I,
    pub block_len2: u32,
}

impl<Input, En: PcapEndianness> PcapNGBlockParser<Input, En>
    for SystemdJournalExportBlock<Input::Slice>
where
    Input: Stream<Token = u8, Slice = Input> + StreamIsPartial,
    <Input as Stream>::Slice: AsBytes,
{
    const HDR_SZ: usize = 12;
    const MAGIC: u32 = SJE_MAGIC;

    type Output = SystemdJournalExportBlock<Input::Slice>;

    fn inner_parse<E: ParseError<Input>>(
        block_type: u32,
        block_len1: u32,
        i: Input,
        block_len2: u32,
    ) -> IResult<Input, Self::Output, E> {
        let (empty, data) = take(i.eof_offset()).parse_next(i)?;
        let block = SystemdJournalExportBlock {
            block_type,
            block_len1,
            data,
            block_len2,
        };
        Ok((empty, block))
    }
}

/// Parse a Systemd Journal Export Block (little-endian)
pub fn parse_systemdjournalexportblock_le<I>(
    i: I,
) -> IResult<I, SystemdJournalExportBlock<I>, PcapError<I>>
where
    I: Stream<Token = u8, Slice = I> + StreamIsPartial,
    <I as Stream>::Slice: AsBytes,
{
    ng_block_parser::<I, SystemdJournalExportBlock<_>, PcapLE, _, _>().parse_next(i)
}

/// Parse a Systemd Journal Export Block (big-endian)
pub fn parse_systemdjournalexportblock_be<I>(
    i: I,
) -> IResult<I, SystemdJournalExportBlock<I>, PcapError<I>>
where
    I: Stream<Token = u8, Slice = I> + StreamIsPartial,
    <I as Stream>::Slice: AsBytes,
{
    ng_block_parser::<I, SystemdJournalExportBlock<_>, PcapBE, _, _>().parse_next(i)
}
