use nom::bytes::streaming::{tag, take};
use nom::combinator::map;
use nom::error::{ErrorKind, ParseError};
use nom::multi::many_till;
use nom::{Err, IResult};
use rusticata_macros::{align32, newtype_enum};

use crate::endianness::{PcapBE, PcapEndianness, PcapLE};
use crate::{opt_parse_options, PcapError, PcapNGOption, NRB_MAGIC};

use super::*;

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
pub struct NameRecord<'a> {
    pub record_type: NameRecordType,
    pub record_value: &'a [u8],
}

impl<'a> NameRecord<'a> {
    pub const END: NameRecord<'static> = NameRecord {
        record_type: NameRecordType::End,
        record_value: &[],
    };
}

#[derive(Debug)]
pub struct NameResolutionBlock<'a> {
    pub block_type: u32,
    pub block_len1: u32,
    pub nr: Vec<NameRecord<'a>>,
    pub options: Vec<PcapNGOption<'a>>,
    pub block_len2: u32,
}

impl<'a, En: PcapEndianness> PcapNGBlockParser<'a, En, NameResolutionBlock<'a>>
    for NameResolutionBlock<'a>
{
    const HDR_SZ: usize = 12;
    const MAGIC: u32 = NRB_MAGIC;

    fn inner_parse<E: ParseError<&'a [u8]>>(
        block_type: u32,
        block_len1: u32,
        i: &'a [u8],
        block_len2: u32,
    ) -> IResult<&'a [u8], NameResolutionBlock<'a>, E> {
        let start_i = i;
        // caller function already tested header type(magic) and length
        // read records
        let (i, nr) = parse_name_record_list::<En, E>(i)?;
        // read options
        let current_offset = 12 + (i.as_ptr() as usize) - (start_i.as_ptr() as usize);
        let (i, options) = opt_parse_options::<En, E>(i, block_len1 as usize, current_offset)?;
        if block_len2 != block_len1 {
            return Err(Err::Error(E::from_error_kind(i, ErrorKind::Verify)));
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

fn parse_name_record<'a, En: PcapEndianness, E: ParseError<&'a [u8]>>(
    i: &'a [u8],
) -> IResult<&'a [u8], NameRecord, E> {
    let (i, record_type) = En::parse_u16(i)?;
    let (i, record_len) = En::parse_u16(i)?;
    let aligned_len = align32!(record_len as u32);
    let (i, record_value) = take(aligned_len)(i)?;
    let name_record = NameRecord {
        record_type: NameRecordType(record_type),
        record_value,
    };
    Ok((i, name_record))
}

fn parse_name_record_list<'a, En: PcapEndianness, E: ParseError<&'a [u8]>>(
    i: &'a [u8],
) -> IResult<&'a [u8], Vec<NameRecord>, E> {
    map(
        many_till(parse_name_record::<En, E>, tag(b"\x00\x00\x00\x00")),
        |(mut v, _)| {
            v.push(NameRecord::END);
            v
        },
    )(i)
}

/// Parse a Name Resolution Block (little-endian)
#[inline]
pub fn parse_nameresolutionblock_le(
    i: &[u8],
) -> IResult<&[u8], NameResolutionBlock, PcapError<&[u8]>> {
    ng_block_parser::<NameResolutionBlock, PcapLE, _, _>()(i)
}

/// Parse a Name Resolution Block (big-endian)
#[inline]
pub fn parse_nameresolutionblock_be(
    i: &[u8],
) -> IResult<&[u8], NameResolutionBlock, PcapError<&[u8]>> {
    ng_block_parser::<NameResolutionBlock, PcapBE, _, _>()(i)
}
