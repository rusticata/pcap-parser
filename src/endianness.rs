use winnow::error::ParseError;
use winnow::number::streaming::{be_u16, be_u32, le_u16, le_u32};
use winnow::stream::{AsBytes, Stream, StreamIsPartial};
use winnow::IResult;

pub(crate) struct PcapBE;
pub(crate) struct PcapLE;

pub(crate) trait PcapEndianness {
    fn native_u32(n: u32) -> u32;

    fn parse_u16<'a, E: ParseError<&'a [u8]>>(i: &'a [u8]) -> IResult<&'a [u8], u16, E>;
    fn parse_u32<'a, E: ParseError<&'a [u8]>>(i: &'a [u8]) -> IResult<&'a [u8], u32, E>;

    fn parse_i64_gen<I, E: ParseError<I>>(i: I) -> IResult<I, i64, E>
    where
        I: Stream<Token = u8> + StreamIsPartial,
        <I as Stream>::Slice: AsBytes;

    fn parse_u16_gen<I, E: ParseError<I>>(i: I) -> IResult<I, u16, E>
    where
        I: Stream<Token = u8> + StreamIsPartial,
        <I as Stream>::Slice: AsBytes;
    fn parse_u32_gen<I, E: ParseError<I>>(i: I) -> IResult<I, u32, E>
    where
        I: Stream<Token = u8> + StreamIsPartial,
        <I as Stream>::Slice: AsBytes;
    fn parse_u64_gen<I, E: ParseError<I>>(i: I) -> IResult<I, u64, E>
    where
        I: Stream<Token = u8> + StreamIsPartial,
        <I as Stream>::Slice: AsBytes;

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

    fn parse_i64_gen<I, E: ParseError<I>>(i: I) -> IResult<I, i64, E>
    where
        I: Stream<Token = u8> + StreamIsPartial,
        <I as Stream>::Slice: AsBytes,
    {
        winnow::number::be_i64(i)
    }

    fn parse_u16_gen<I, E: ParseError<I>>(i: I) -> IResult<I, u16, E>
    where
        I: Stream<Token = u8> + StreamIsPartial,
        <I as Stream>::Slice: AsBytes,
    {
        winnow::number::be_u16(i)
    }

    fn parse_u32_gen<I, E: ParseError<I>>(i: I) -> IResult<I, u32, E>
    where
        I: Stream<Token = u8> + StreamIsPartial,
        <I as Stream>::Slice: AsBytes,
    {
        winnow::number::be_u32(i)
    }

    fn parse_u64_gen<I, E: ParseError<I>>(i: I) -> IResult<I, u64, E>
    where
        I: Stream<Token = u8> + StreamIsPartial,
        <I as Stream>::Slice: AsBytes,
    {
        winnow::number::be_u64(i)
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

    fn parse_i64_gen<I, E: ParseError<I>>(i: I) -> IResult<I, i64, E>
    where
        I: Stream<Token = u8> + StreamIsPartial,
        <I as Stream>::Slice: AsBytes,
    {
        winnow::number::le_i64(i)
    }

    fn parse_u16_gen<I, E: ParseError<I>>(i: I) -> IResult<I, u16, E>
    where
        I: Stream<Token = u8> + StreamIsPartial,
        <I as Stream>::Slice: AsBytes,
    {
        winnow::number::le_u16(i)
    }

    fn parse_u32_gen<I, E: ParseError<I>>(i: I) -> IResult<I, u32, E>
    where
        I: Stream<Token = u8> + StreamIsPartial,
        <I as Stream>::Slice: AsBytes,
    {
        winnow::number::le_u32(i)
    }

    fn parse_u64_gen<I, E: ParseError<I>>(i: I) -> IResult<I, u64, E>
    where
        I: Stream<Token = u8> + StreamIsPartial,
        <I as Stream>::Slice: AsBytes,
    {
        winnow::number::le_u64(i)
    }

    #[inline]
    fn u32_from_bytes(i: [u8; 4]) -> u32 {
        u32::from_le_bytes(i)
    }
}
