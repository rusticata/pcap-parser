use core::convert::TryFrom;
use winnow::{
    error::{ErrMode, ErrorKind, ParseError},
    stream::{AsBytes, Stream, StreamIsPartial},
    IResult, Parser,
};

use super::blockparser::{ng_block_parser, PcapNGBlockParser};
use super::{build_ts_resolution, opt_parse_options, OptionCode, PcapNGOption, IDB_MAGIC};
use crate::endianness::{PcapBE, PcapEndianness, PcapLE};
use crate::{Linktype, PcapError};

/// An Interface Description Block (IDB) is the container for information
/// describing an interface on which packet data is captured.
#[derive(Debug)]
pub struct InterfaceDescriptionBlock<I: AsBytes> {
    pub block_type: u32,
    pub block_len1: u32,
    pub linktype: Linktype,
    pub reserved: u16,
    pub snaplen: u32,
    pub options: Vec<PcapNGOption<I>>,
    pub block_len2: u32,
    pub if_tsresol: u8,
    pub if_tsoffset: i64,
}

impl<I: AsBytes> InterfaceDescriptionBlock<I> {
    /// Decode the interface time resolution, in units per second
    ///
    /// Return the resolution, or `None` if the resolution is invalid (for ex. greater than `2^64`)
    #[inline]
    pub fn ts_resolution(&self) -> Option<u64> {
        build_ts_resolution(self.if_tsresol)
    }

    /// Return the interface timestamp offset
    #[inline]
    pub fn ts_offset(&self) -> i64 {
        self.if_tsoffset
    }
}

impl<Input, En: PcapEndianness> PcapNGBlockParser<Input, En>
    for InterfaceDescriptionBlock<Input::Slice>
where
    Input: Stream<Token = u8, Slice = Input> + StreamIsPartial,
    <Input as Stream>::Slice: AsBytes,
{
    const HDR_SZ: usize = 20;
    const MAGIC: u32 = IDB_MAGIC;

    type Output = InterfaceDescriptionBlock<Input::Slice>;

    fn inner_parse<E: ParseError<Input>>(
        block_type: u32,
        block_len1: u32,
        i: Input,
        block_len2: u32,
    ) -> IResult<Input, Self::Output, E> {
        // caller function already tested header type(magic) and length
        // read end of header
        let (i, linktype) = En::parse_u16_gen(i)?;
        let (i, reserved) = En::parse_u16_gen(i)?;
        let (i, snaplen) = En::parse_u32_gen(i)?;
        // read options
        let (i, options) = opt_parse_options::<_, En, E>(i, block_len1 as usize, 20)?;
        if block_len2 != block_len1 {
            return Err(ErrMode::Backtrack(E::from_error_kind(i, ErrorKind::Verify)));
        }
        let (if_tsresol, if_tsoffset) = if_extract_tsoffset_and_tsresol(&options);
        let block = InterfaceDescriptionBlock {
            block_type,
            block_len1,
            linktype: Linktype(linktype as i32),
            reserved,
            snaplen,
            options,
            block_len2,
            if_tsresol,
            if_tsoffset,
        };
        Ok((i, block))
    }
}

/// Parse an Interface Packet Block (little-endian)
pub fn parse_interfacedescriptionblock_le<I>(
    i: I,
) -> IResult<I, InterfaceDescriptionBlock<I>, PcapError<I>>
where
    I: Stream<Token = u8, Slice = I> + StreamIsPartial,
    <I as Stream>::Slice: AsBytes,
{
    ng_block_parser::<I, InterfaceDescriptionBlock<_>, PcapLE, _, _>().parse_next(i)
}

/// Parse an Interface Packet Block (big-endian)
pub fn parse_interfacedescriptionblock_be<I>(
    i: I,
) -> IResult<I, InterfaceDescriptionBlock<I>, PcapError<I>>
where
    I: Stream<Token = u8, Slice = I> + StreamIsPartial,
    <I as Stream>::Slice: AsBytes,
{
    ng_block_parser::<I, InterfaceDescriptionBlock<_>, PcapBE, _, _>().parse_next(i)
}

fn if_extract_tsoffset_and_tsresol<I: AsBytes>(options: &[PcapNGOption<I>]) -> (u8, i64) {
    let mut if_tsresol: u8 = 6;
    let mut if_tsoffset: i64 = 0;
    for opt in options {
        let value = opt.value();
        match opt.code {
            OptionCode::IfTsresol => {
                if !value.is_empty() {
                    if_tsresol = value[0];
                }
            }
            OptionCode::IfTsoffset => {
                if value.len() >= 8 {
                    let int_bytes = <[u8; 8]>::try_from(&value[..8]).expect("Convert bytes to i64");
                    if_tsoffset = i64::from_le_bytes(int_bytes);
                }
            }
            _ => (),
        }
    }
    (if_tsresol, if_tsoffset)
}
