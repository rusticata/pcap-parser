use rusticata_macros::align32;
use std::convert::TryFrom;
use winnow::{
    bytes::take,
    error::ParseError,
    multi::many0,
    stream::{AsBytes, Stream, StreamIsPartial},
    IResult,
};

use crate::endianness::{PcapBE, PcapEndianness, PcapLE};

use super::OptionCode;

#[derive(Debug)]
pub struct PcapNGOption<I: AsBytes> {
    pub code: OptionCode,
    pub len: u16,
    pub value: I,
}

impl<I: AsBytes> PcapNGOption<I> {
    /// Return a reference to the option value, as raw bytes (not related to the `len` field)
    #[inline]
    pub fn value(&self) -> &[u8] {
        self.value.as_bytes()
    }

    /// Return a reference to the option value, using the `len` field to limit it, or None if length is invalid
    pub fn as_bytes(&self) -> Option<&[u8]> {
        let len = usize::from(self.len);
        let value = self.value();
        if len <= value.len() {
            Some(&value[..len])
        } else {
            None
        }
    }

    /// Return the option value interpreted as i32, or None
    ///
    /// Option data length and declared must be exactly 4 bytes
    pub fn as_i32_le(&self) -> Option<i32> {
        let value = self.value();
        if self.len == 8 && value.len() == 8 {
            <[u8; 4]>::try_from(value).ok().map(i32::from_le_bytes)
        } else {
            None
        }
    }

    /// Return the option value interpreted as u32, or None
    ///
    /// Option data length and declared must be exactly 4 bytes
    pub fn as_u32_le(&self) -> Option<u32> {
        let value = self.value();
        if self.len == 8 && value.len() == 8 {
            <[u8; 4]>::try_from(value).ok().map(u32::from_le_bytes)
        } else {
            None
        }
    }

    /// Return the option value interpreted as i64, or None
    ///
    /// Option data length and declared must be exactly 8 bytes
    pub fn as_i64_le(&self) -> Option<i64> {
        let value = self.value();
        if self.len == 8 && value.len() == 8 {
            <[u8; 8]>::try_from(value).ok().map(i64::from_le_bytes)
        } else {
            None
        }
    }

    /// Return the option value interpreted as u64, or None
    ///
    /// Option data length and declared must be exactly 8 bytes
    pub fn as_u64_le(&self) -> Option<u64> {
        let value = self.value();
        if self.len == 8 && value.len() == 8 {
            <[u8; 8]>::try_from(value).ok().map(u64::from_le_bytes)
        } else {
            None
        }
    }
}

#[inline]
pub fn parse_option_le<'i, E: ParseError<&'i [u8]>>(
    i: &'i [u8],
) -> IResult<&'i [u8], PcapNGOption<&[u8]>, E> {
    parse_option::<_, PcapLE, E>(i)
}

#[inline]
pub fn parse_option_be<'i, E: ParseError<&'i [u8]>>(
    i: &'i [u8],
) -> IResult<&'i [u8], PcapNGOption<&[u8]>, E> {
    parse_option::<_, PcapBE, E>(i)
}

pub(crate) fn parse_option<I, En: PcapEndianness, E: ParseError<I>>(
    i: I,
) -> IResult<I, PcapNGOption<I::Slice>, E>
where
    I: Stream<Token = u8>,
    I: StreamIsPartial,
    <I as Stream>::Slice: AsBytes,
{
    let (i, code) = En::parse_u16_gen(i)?;
    let (i, len) = En::parse_u16_gen(i)?;
    let (i, value) = take(align32!(len as u32))(i)?;
    let option = PcapNGOption {
        code: OptionCode(code),
        len,
        value,
    };
    Ok((i, option))
}

pub(crate) fn opt_parse_options<I, En: PcapEndianness, E: ParseError<I>>(
    i: I,
    len: usize,
    opt_offset: usize,
) -> IResult<I, Vec<PcapNGOption<I::Slice>>, E>
where
    // the Slice=I bound is caused by the fact we are re-parsing
    I: Stream<Token = u8, Slice = I>,
    I: StreamIsPartial,
    <I as Stream>::Slice: AsBytes,
{
    if len > opt_offset {
        // take subslice
        let (rem, slice) = take(len - opt_offset)(i)?;
        // read a Vec<PcapNGOption> from it
        let (_, output): (_, Vec<_>) = many0(parse_option::<_, En, E>)(slice)?;
        Ok((rem, output))
    } else {
        Ok((i, Vec::new()))
    }
}
