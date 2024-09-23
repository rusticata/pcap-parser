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
    IsbStartTime = 2,
    ShbOs = 3,
    IfDescription = 3,
    IsbEndTime = 3,
    ShbUserAppl = 4,
    IfIpv4Addr = 4,
    IsbIfRecv = 4,
    IsbIfDrop = 5,
    IfMacAddr = 6,
    IsbFilterAccept = 6,
    IfEuiAddr = 7,
    IsbOsDrop = 7,
    IfSpeed = 8,
    IsbUsrDeliv = 8,
    IfTsresol = 9,
    IfFilter = 11,
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

/// A PcapNG option
#[derive(Debug)]
pub struct PcapNGOption<'a> {
    /// The numeric code for the option
    ///
    /// Note that codes are relative to the block type, and same codes are used for different
    /// things (for ex 2 is `shb_hardware` if the block is a SHB, but 2 is `if_name` for an IDB)
    pub code: OptionCode,
    /// The declared length for the option
    ///
    /// Note that `value.len()` can be greater than `len`, because data is padded to a 32-bit boundary
    pub len: u16,
    /// The raw value (including padding) of the option
    ///
    /// See [PcapNGOption::as_bytes] to get the value truncated to `len`.
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
) -> IResult<&'i [u8], PcapNGOption<'i>, E> {
    parse_option::<PcapLE, E>(i)
}

/// Parse a pcap-ng Option (big-endian)
#[inline]
pub fn parse_option_be<'i, E: ParseError<&'i [u8]>>(
    i: &'i [u8],
) -> IResult<&'i [u8], PcapNGOption<'i>, E> {
    parse_option::<PcapBE, E>(i)
}

pub(crate) fn parse_option<'i, En: PcapEndianness, E: ParseError<&'i [u8]>>(
    i: &'i [u8],
) -> IResult<&'i [u8], PcapNGOption<'i>, E> {
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
) -> IResult<&'i [u8], Vec<PcapNGOption<'i>>, E> {
    if len > opt_offset {
        map_parser(
            take(len - opt_offset),
            many0(complete(parse_option::<En, E>)),
        )(i)
    } else {
        Ok((i, Vec::new()))
    }
}

#[inline]
pub(crate) fn options_find_map<'a, F, O>(
    options: &'a [PcapNGOption],
    code: OptionCode,
    f: F,
) -> Option<Result<O, PcapNGOptionError>>
where
    F: Fn(&'a PcapNGOption) -> Result<O, PcapNGOptionError>,
{
    options
        .iter()
        .find_map(|opt| if opt.code == code { Some(f(opt)) } else { None })
}

pub(crate) fn options_get_as_bytes<'a>(
    options: &'a [PcapNGOption],
    code: OptionCode,
) -> Option<Result<&'a [u8], PcapNGOptionError>> {
    options_find_map(options, code, |opt| opt.as_bytes())
}

pub(crate) fn options_get_as_str<'a>(
    options: &'a [PcapNGOption],
    code: OptionCode,
) -> Option<Result<&'a str, PcapNGOptionError>> {
    options_find_map(options, code, |opt| opt.as_str())
}

pub(crate) fn options_get_as_u8(
    options: &[PcapNGOption],
    code: OptionCode,
) -> Option<Result<u8, PcapNGOptionError>> {
    options_find_map(options, code, |opt| {
        let value = opt.value();
        if opt.len == 1 && !value.is_empty() {
            Ok(value[0])
        } else {
            Err(PcapNGOptionError::InvalidLength)
        }
    })
}

pub(crate) fn options_get_as_i64_le(
    options: &[PcapNGOption],
    code: OptionCode,
) -> Option<Result<i64, PcapNGOptionError>> {
    options_find_map(options, code, |opt| opt.as_i64_le())
}

pub(crate) fn options_get_as_u64_le(
    options: &[PcapNGOption],
    code: OptionCode,
) -> Option<Result<u64, PcapNGOptionError>> {
    options_find_map(options, code, |opt| opt.as_u64_le())
}

pub(crate) fn options_get_as_ts(
    options: &[PcapNGOption],
    code: OptionCode,
) -> Option<Result<(u32, u32), PcapNGOptionError>> {
    options_find_map(options, code, |opt| {
        let value = opt.value();
        if opt.len == 8 && value.len() == 8 {
            let bytes_ts_high =
                <[u8; 4]>::try_from(&value[..4]).or(Err(PcapNGOptionError::InvalidLength))?;
            let bytes_ts_low =
                <[u8; 4]>::try_from(&value[4..8]).or(Err(PcapNGOptionError::InvalidLength))?;
            let ts_high = u32::from_le_bytes(bytes_ts_high);
            let ts_low = u32::from_le_bytes(bytes_ts_low);
            Ok((ts_high, ts_low))
        } else {
            Err(PcapNGOptionError::InvalidLength)
        }
    })
}
