use crate::pcapng::*;
use nom::error::ParseError;
use nom::number::streaming::{be_u32, le_u32};
use nom::IResult;

pub(crate) struct PcapBE;
pub(crate) struct PcapLE;

pub(crate) trait PcapEndianness {
    fn parse_u32<'a, E: ParseError<&'a [u8]>>(i: &'a [u8]) -> IResult<&'a [u8], u32, E>;

    fn u32_from_bytes(i: [u8; 4]) -> u32;

    fn opt_parse_options<'a, E: ParseError<&'a [u8]>>(
        i: &'a [u8],
        len: usize,
        opt_offset: usize,
    ) -> IResult<&'a [u8], Vec<PcapNGOption>, E>;
}

impl PcapEndianness for PcapBE {
    #[inline]
    fn parse_u32<'a, E: ParseError<&'a [u8]>>(i: &'a [u8]) -> IResult<&'a [u8], u32, E> {
        be_u32(i)
    }

    #[inline]
    fn u32_from_bytes(i: [u8; 4]) -> u32 {
        u32::from_be_bytes(i)
    }

    #[inline]
    fn opt_parse_options<'a, E: ParseError<&'a [u8]>>(
        i: &'a [u8],
        len: usize,
        opt_offset: usize,
    ) -> IResult<&'a [u8], Vec<PcapNGOption>, E> {
        opt_parse_options_be(i, len, opt_offset)
    }
}

impl PcapEndianness for PcapLE {
    #[inline]
    fn parse_u32<'a, E: ParseError<&'a [u8]>>(i: &'a [u8]) -> IResult<&'a [u8], u32, E> {
        le_u32(i)
    }

    #[inline]
    fn u32_from_bytes(i: [u8; 4]) -> u32 {
        u32::from_le_bytes(i)
    }

    #[inline]
    fn opt_parse_options<'a, E: ParseError<&'a [u8]>>(
        i: &'a [u8],
        len: usize,
        opt_offset: usize,
    ) -> IResult<&'a [u8], Vec<PcapNGOption>, E> {
        opt_parse_options(i, len, opt_offset)
    }
}
