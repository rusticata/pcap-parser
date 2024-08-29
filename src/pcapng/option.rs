use std::borrow::Cow;
use std::convert::TryFrom;
use std::fmt;

use nom::combinator::{complete, map_parser};
use nom::multi::many0;
use nom::IResult;
use nom::{bytes::streaming::take, error::ParseError};
use rusticata_macros::{align32, newtype_enum};

use crate::endianness::{PcapBE, PcapEndianness, PcapLE};

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct OptionCode(pub u16);

newtype_enum! {
impl debug OptionCode {
    EndOfOpt = 0,
    Comment = 1,
    ShbHardware = 2,
    IfName = 2,
    ShbOs = 3,
    IfDescription = 3,
    ShbUserAppl = 4,
    IfIpv4Addr = 4,
    IfTsresol = 9,
    IfOs = 12,
    IfTsoffset = 14,
    Custom2988 = 2988,
    Custom2989 = 2989,
    Custom19372 = 19372,
    Custom19373 = 19373,
}
}

/// The error type which is returned when calling functions on [PcapNGOption]
#[derive(Debug, PartialEq)]
pub enum PcapNGOptionError {
    InvalidLength,
    Utf8Error,
}

impl fmt::Display for PcapNGOptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PcapNGOptionError::InvalidLength => write!(f, "Invalid length"),
            PcapNGOptionError::Utf8Error => write!(f, "Invalid UTF-8 string"),
        }
    }
}

impl std::error::Error for PcapNGOptionError {}

#[derive(Debug)]
pub struct PcapNGOption<'a> {
    pub code: OptionCode,
    pub len: u16,
    pub value: Cow<'a, [u8]>,
}

impl<'a> PcapNGOption<'a> {
    /// Return a reference to the option value, as raw bytes (not related to the `len` field)
    #[inline]
    pub fn value(&self) -> &[u8] {
        self.value.as_ref()
    }

    /// Return a reference to the option value, using the `len` field to limit it, or None if length is invalid
    pub fn as_bytes(&self) -> Result<&[u8], PcapNGOptionError> {
        let len = usize::from(self.len);
        if len <= self.value.len() {
            Ok(&self.value[..len])
        } else {
            Err(PcapNGOptionError::InvalidLength)
        }
    }

    /// Return the option value interpreted as string
    ///
    /// Returns an error if the length of the option is invalid, or if the value is not valid UTF-8.
    pub fn as_str(&self) -> Result<&str, PcapNGOptionError> {
        self.as_bytes()
            .and_then(|b| std::str::from_utf8(b).or(Err(PcapNGOptionError::Utf8Error)))
    }

    /// Return the option value interpreted as i32, or an error
    ///
    /// Option data length and declared must be exactly 4 bytes
    pub fn as_i32_le(&self) -> Result<i32, PcapNGOptionError> {
        if self.len != 4 {
            return Err(PcapNGOptionError::InvalidLength);
        }
        <[u8; 4]>::try_from(self.value())
            .map(i32::from_le_bytes)
            .or(Err(PcapNGOptionError::InvalidLength))
    }

    /// Return the option value interpreted as u32, or an error
    ///
    /// Option data length and declared must be exactly 4 bytes
    pub fn as_u32_le(&self) -> Result<u32, PcapNGOptionError> {
        if self.len != 4 {
            return Err(PcapNGOptionError::InvalidLength);
        }
        <[u8; 4]>::try_from(self.value())
            .map(u32::from_le_bytes)
            .or(Err(PcapNGOptionError::InvalidLength))
    }

    /// Return the option value interpreted as i64, or an error
    ///
    /// Option data length and declared must be exactly 8 bytes
    pub fn as_i64_le(&self) -> Result<i64, PcapNGOptionError> {
        if self.len != 8 {
            return Err(PcapNGOptionError::InvalidLength);
        }
        <[u8; 8]>::try_from(self.value())
            .map(i64::from_le_bytes)
            .or(Err(PcapNGOptionError::InvalidLength))
    }

    /// Return the option value interpreted as u64, or an error
    ///
    /// Option data length and declared must be exactly 8 bytes
    pub fn as_u64_le(&self) -> Result<u64, PcapNGOptionError> {
        if self.len != 8 {
            return Err(PcapNGOptionError::InvalidLength);
        }
        <[u8; 8]>::try_from(self.value())
            .map(u64::from_le_bytes)
            .or(Err(PcapNGOptionError::InvalidLength))
    }
}

/// Parse a pcap-ng Option (little-endian)
#[inline]
pub fn parse_option_le<'i, E: ParseError<&'i [u8]>>(
    i: &'i [u8],
) -> IResult<&'i [u8], PcapNGOption, E> {
    parse_option::<PcapLE, E>(i)
}

/// Parse a pcap-ng Option (big-endian)
#[inline]
pub fn parse_option_be<'i, E: ParseError<&'i [u8]>>(
    i: &'i [u8],
) -> IResult<&'i [u8], PcapNGOption, E> {
    parse_option::<PcapBE, E>(i)
}

pub(crate) fn parse_option<'i, En: PcapEndianness, E: ParseError<&'i [u8]>>(
    i: &'i [u8],
) -> IResult<&'i [u8], PcapNGOption, E> {
    let (i, code) = En::parse_u16(i)?;
    let (i, len) = En::parse_u16(i)?;
    let (i, value) = take(align32!(len as u32))(i)?;
    let option = PcapNGOption {
        code: OptionCode(code),
        len,
        value: Cow::Borrowed(value),
    };
    Ok((i, option))
}

pub(crate) fn opt_parse_options<'i, En: PcapEndianness, E: ParseError<&'i [u8]>>(
    i: &'i [u8],
    len: usize,
    opt_offset: usize,
) -> IResult<&'i [u8], Vec<PcapNGOption>, E> {
    if len > opt_offset {
        map_parser(
            take(len - opt_offset),
            many0(complete(parse_option::<En, E>)),
        )(i)
    } else {
        Ok((i, Vec::new()))
    }
}

pub(crate) fn options_get_as_string<'a>(
    options: &'a [PcapNGOption],
    code: OptionCode,
) -> Option<Result<&'a str, PcapNGOptionError>> {
    options.iter().find_map(|opt| {
        if opt.code == code {
            Some(opt.as_str())
        } else {
            None
        }
    })
}
