use rusticata_macros::{align32, newtype_enum};
use winnow::{
    bytes::take,
    error::{ErrMode, ErrorKind, ParseError},
    multi::many_till0,
    stream::{AsBytes, Stream, StreamIsPartial},
    IResult, Parser,
};

use super::blockparser::{ng_block_parser, PcapNGBlockParser};
use super::{opt_parse_options, PcapNGOption, NRB_MAGIC};
use crate::endianness::{PcapBE, PcapEndianness, PcapLE};
use crate::PcapError;

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct NameRecordType(pub u16);

newtype_enum! {
    impl debug NameRecordType {
        End = 0,
        Ipv4 = 1,
        Ipv6 = 2
    }
}

#[derive(Debug)]
pub struct NameRecord<I: AsBytes> {
    pub record_type: NameRecordType,
    pub record_value: I,
}

impl<I: AsBytes> NameRecord<I> {
    //     pub const END: NameRecord<I> = NameRecord {
    //         record_type: NameRecordType::End,
    //         record_value: I::from(&[]), // FIXME: we can't define END like this (even `empty(I)` is dynamic)
    //     };

    #[inline]
    pub const fn is_end(&self) -> bool {
        self.record_type.0 == NameRecordType::End.0
    }
}

fn parse_name_record<I, En: PcapEndianness, E: ParseError<I>>(i: I) -> IResult<I, NameRecord<I>, E>
where
    I: Stream<Token = u8, Slice = I> + StreamIsPartial,
    <I as Stream>::Slice: AsBytes,
{
    let (i, record_type) = En::parse_u16_gen(i)?;
    let (i, record_len) = En::parse_u16_gen(i)?;
    let aligned_len = align32!(record_len as u32);
    let (i, record_value) = take(aligned_len)(i)?;
    let name_record = NameRecord {
        record_type: NameRecordType(record_type),
        record_value,
    };
    Ok((i, name_record))
}

fn parse_name_record_list<I, En: PcapEndianness, E: ParseError<I>>(
    i: I,
) -> IResult<I, Vec<NameRecord<I>>, E>
where
    I: Stream<Token = u8, Slice = I> + StreamIsPartial,
    <I as Stream>::Slice: AsBytes,
{
    // workaround to create an empty I (I is not Default)
    let (i, empty) = take(0u8)(i)?;
    let (rem, (mut v, _)): (_, (Vec<_>, _)) =
        many_till0(parse_name_record::<_, En, E>, (0u8, 0u8, 0u8, 0u8))(i)?;
    // NOTE: we can't use .map() because it expects a Fn(), which cannot take ownership of `empty`
    v.push(NameRecord {
        record_type: NameRecordType::End,
        record_value: empty,
    });
    Ok((rem, v))
}

#[derive(Debug)]
pub struct NameResolutionBlock<I: AsBytes> {
    pub block_type: u32,
    pub block_len1: u32,
    pub nr: Vec<NameRecord<I>>,
    pub options: Vec<PcapNGOption<I>>,
    pub block_len2: u32,
}

impl<Input, En: PcapEndianness> PcapNGBlockParser<Input, En> for NameResolutionBlock<Input::Slice>
where
    Input: Stream<Token = u8, Slice = Input> + StreamIsPartial,
    <Input as Stream>::Slice: AsBytes,
{
    const HDR_SZ: usize = 12;
    const MAGIC: u32 = NRB_MAGIC;

    type Output = NameResolutionBlock<Input::Slice>;

    fn inner_parse<E: ParseError<Input>>(
        block_type: u32,
        block_len1: u32,
        i: Input,
        block_len2: u32,
    ) -> IResult<Input, Self::Output, E> {
        let start_rem = i.eof_offset();
        // caller function already tested header type(magic) and length
        // read records
        let (i, nr) = parse_name_record_list::<_, En, E>(i)?;
        // read options
        let current_offset = 12 + (start_rem - i.eof_offset());
        let (i, options) = opt_parse_options::<_, En, E>(i, block_len1 as usize, current_offset)?;
        if block_len2 != block_len1 {
            return Err(ErrMode::Backtrack(E::from_error_kind(i, ErrorKind::Verify)));
        }
        let block = NameResolutionBlock {
            block_type,
            block_len1,
            nr,
            options,
            block_len2,
        };
        Ok((i, block))
    }
}

/// Parse a Name Resolution Block (little-endian)
pub fn parse_nameresolutionblock_le<I>(i: I) -> IResult<I, NameResolutionBlock<I>, PcapError<I>>
where
    I: Stream<Token = u8, Slice = I> + StreamIsPartial,
    <I as Stream>::Slice: AsBytes,
{
    ng_block_parser::<I, NameResolutionBlock<_>, PcapLE, _, _>().parse_next(i)
}

/// Parse a Name Resolution Block (big-endian)
pub fn parse_nameresolutionblock_be<I>(i: I) -> IResult<I, NameResolutionBlock<I>, PcapError<I>>
where
    I: Stream<Token = u8, Slice = I> + StreamIsPartial,
    <I as Stream>::Slice: AsBytes,
{
    ng_block_parser::<I, NameResolutionBlock<_>, PcapBE, _, _>().parse_next(i)
}
