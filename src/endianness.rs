use nom::error::ParseError;
use nom::number::streaming::{be_u16, be_u32, le_u16, le_u32};
use nom::IResult;

pub(crate) struct PcapBE;
pub(crate) struct PcapLE;

pub(crate) trait PcapEndianness {
    fn native_u32(n: u32) -> u32;

    fn parse_u16<'a, E: ParseError<&'a [u8]>>(i: &'a [u8]) -> IResult<&'a [u8], u16, E>;
    fn parse_u32<'a, E: ParseError<&'a [u8]>>(i: &'a [u8]) -> IResult<&'a [u8], u32, E>;

    fn u32_from_bytes(i: [u8; 4]) -> u32;
}

impl PcapEndianness for PcapBE {
    #[inline]
    fn native_u32(n: u32) -> u32 {
        u32::from_be(n)
    }

    #[inline]
    fn parse_u16<'a, E: ParseError<&'a [u8]>>(i: &'a [u8]) -> IResult<&'a [u8], u16, E> {
        be_u16(i)
    }

    #[inline]
    fn parse_u32<'a, E: ParseError<&'a [u8]>>(i: &'a [u8]) -> IResult<&'a [u8], u32, E> {
        be_u32(i)
    }

    #[inline]
    fn u32_from_bytes(i: [u8; 4]) -> u32 {
        u32::from_be_bytes(i)
    }
}

impl PcapEndianness for PcapLE {
    #[inline]
    fn native_u32(n: u32) -> u32 {
        u32::from_le(n)
    }

    #[inline]
    fn parse_u16<'a, E: ParseError<&'a [u8]>>(i: &'a [u8]) -> IResult<&'a [u8], u16, E> {
        le_u16(i)
    }

    #[inline]
    fn parse_u32<'a, E: ParseError<&'a [u8]>>(i: &'a [u8]) -> IResult<&'a [u8], u32, E> {
        le_u32(i)
    }

    #[inline]
    fn u32_from_bytes(i: [u8; 4]) -> u32 {
        u32::from_le_bytes(i)
    }
}
