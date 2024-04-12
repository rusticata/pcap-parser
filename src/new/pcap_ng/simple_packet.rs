use winnow::{
    bytes::take,
    error::ParseError,
    stream::{AsBytes, Stream, StreamIsPartial},
    IResult, Parser,
};

use super::blockparser::{ng_block_parser, PcapNGBlockParser};
use super::SPB_MAGIC;
use crate::endianness::{PcapBE, PcapEndianness, PcapLE};
use crate::PcapError;

/// The Simple Packet Block (SPB) is a lightweight container for storing
/// the packets coming from the network.
///
/// This struct is a thin abstraction layer, and stores the raw block data.
/// For ex the `data` field is stored with the padding.
/// It implements the `PcapNGPacketBlock` trait, which provides helper functions.
#[derive(Debug)]
pub struct SimplePacketBlock<I: AsBytes> {
    /// Block type (little endian)
    pub block_type: u32,
    pub block_len1: u32,
    /// Original packet length
    pub origlen: u32,
    pub data: I,
    pub block_len2: u32,
}

// FIXME: implement PcapNGPacketBlock  ?!

impl<Input, En: PcapEndianness> PcapNGBlockParser<Input, En> for SimplePacketBlock<Input::Slice>
where
    Input: Stream<Token = u8, Slice = Input> + StreamIsPartial,
    <Input as Stream>::Slice: AsBytes,
{
    const HDR_SZ: usize = 16;
    const MAGIC: u32 = SPB_MAGIC;

    type Output = SimplePacketBlock<Input::Slice>;

    fn inner_parse<E: ParseError<Input>>(
        block_type: u32,
        block_len1: u32,
        i: Input,
        block_len2: u32,
    ) -> IResult<Input, Self::Output, E> {
        // caller function already tested header type(magic) and length
        // read end of header
        let (i, origlen) = En::parse_u32_gen(i)?;
        let (i, data) = take((block_len1 as usize) - 16)(i)?;
        let block = SimplePacketBlock {
            block_type,
            block_len1,
            origlen,
            data,
            block_len2,
        };
        Ok((i, block))
    }
}

/// Parse an Simple Packet Block (little-endian)
///
/// *Note: this function does not remove padding in the `data` field.
/// Use `packet_data` to get field without padding.*
pub fn parse_simplepacketblock_le<I>(i: I) -> IResult<I, SimplePacketBlock<I>, PcapError<I>>
where
    I: Stream<Token = u8, Slice = I> + StreamIsPartial,
    <I as Stream>::Slice: AsBytes,
{
    ng_block_parser::<I, SimplePacketBlock<_>, PcapLE, _, _>().parse_next(i)
}

/// Parse an Interface Packet Block (big-endian)
///
/// *Note: this function does not remove padding in the `data` field.
/// Use `packet_data` to get field without padding.*
pub fn parse_simplepacketblock_be<I>(i: I) -> IResult<I, SimplePacketBlock<I>, PcapError<I>>
where
    I: Stream<Token = u8, Slice = I> + StreamIsPartial,
    <I as Stream>::Slice: AsBytes,
{
    ng_block_parser::<I, SimplePacketBlock<_>, PcapBE, _, _>().parse_next(i)
}
