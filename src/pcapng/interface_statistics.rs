use nom::error::{ErrorKind, ParseError};
use nom::{Err, IResult};

use crate::endianness::{PcapBE, PcapEndianness, PcapLE};
use crate::{opt_parse_options, PcapError, PcapNGOption, ISB_MAGIC};

use super::*;

#[derive(Debug)]
pub struct InterfaceStatisticsBlock<'a> {
    pub block_type: u32,
    pub block_len1: u32,
    pub if_id: u32,
    pub ts_high: u32,
    pub ts_low: u32,
    pub options: Vec<PcapNGOption<'a>>,
    pub block_len2: u32,
}

impl InterfaceStatisticsBlock<'_> {
    /// Return the `isb_starttime` option value, if present
    ///
    /// The returned value is `(ts_high,ts_low)`. To convert to a full timestamp,
    /// use the [build_ts] function with the `ts_offset` and `resolution` values from
    /// the `InterfaceDescriptionBlock` matching `self.if_id`.
    ///
    /// If the option is present multiple times, the first value is returned.
    ///
    /// Returns `None` if option is not present, `Some(Ok(value))` if the value is present and valid,
    /// or `Some(Err(_))` if value is present but invalid
    pub fn isb_starttime(&self) -> Option<Result<(u32, u32), PcapNGOptionError>> {
        options_get_as_ts(&self.options, OptionCode::IsbStartTime)
    }

    /// Return the `isb_endtime` option value, if present
    ///
    /// The returned value is `(ts_high,ts_low)`. To convert to a full timestamp,
    /// use the [build_ts] function with the `ts_offset` and `resolution` values from
    /// the `InterfaceDescriptionBlock` matching `self.if_id`.
    ///
    /// If the option is present multiple times, the first value is returned.
    ///
    /// Returns `None` if option is not present, `Some(Ok(value))` if the value is present and valid,
    /// or `Some(Err(_))` if value is present but invalid
    pub fn isb_endtime(&self) -> Option<Result<(u32, u32), PcapNGOptionError>> {
        options_get_as_ts(&self.options, OptionCode::IsbEndTime)
    }

    /// Return the `isb_ifrecv` option value, if present
    ///
    /// If the option is present multiple times, the first value is returned.
    ///
    /// Returns `None` if option is not present, `Some(Ok(value))` if the value is present and valid,
    /// or `Some(Err(_))` if value is present but invalid
    pub fn isb_ifrecv(&self) -> Option<Result<u64, PcapNGOptionError>> {
        options_get_as_u64_le(&self.options, OptionCode::IsbIfRecv)
    }

    /// Return the `isb_ifdrop` option value, if present
    ///
    /// If the option is present multiple times, the first value is returned.
    ///
    /// Returns `None` if option is not present, `Some(Ok(value))` if the value is present and valid,
    /// or `Some(Err(_))` if value is present but invalid
    pub fn isb_ifdrop(&self) -> Option<Result<u64, PcapNGOptionError>> {
        options_get_as_u64_le(&self.options, OptionCode::IsbIfDrop)
    }

    /// Return the `isb_filteraccept` option value, if present
    ///
    /// If the option is present multiple times, the first value is returned.
    ///
    /// Returns `None` if option is not present, `Some(Ok(value))` if the value is present and valid,
    /// or `Some(Err(_))` if value is present but invalid
    pub fn isb_filteraccept(&self) -> Option<Result<u64, PcapNGOptionError>> {
        options_get_as_u64_le(&self.options, OptionCode::IsbFilterAccept)
    }

    /// Return the `isb_osdrop` option value, if present
    ///
    /// If the option is present multiple times, the first value is returned.
    ///
    /// Returns `None` if option is not present, `Some(Ok(value))` if the value is present and valid,
    /// or `Some(Err(_))` if value is present but invalid
    pub fn isb_osdrop(&self) -> Option<Result<u64, PcapNGOptionError>> {
        options_get_as_u64_le(&self.options, OptionCode::IsbOsDrop)
    }

    /// Return the `isb_usrdeliv` option value, if present
    ///
    /// If the option is present multiple times, the first value is returned.
    ///
    /// Returns `None` if option is not present, `Some(Ok(value))` if the value is present and valid,
    /// or `Some(Err(_))` if value is present but invalid
    pub fn isb_usrdeliv(&self) -> Option<Result<u64, PcapNGOptionError>> {
        options_get_as_u64_le(&self.options, OptionCode::IsbUsrDeliv)
    }
}

impl<'a, En: PcapEndianness> PcapNGBlockParser<'a, En, InterfaceStatisticsBlock<'a>>
    for InterfaceStatisticsBlock<'a>
{
    const HDR_SZ: usize = 24;
    const MAGIC: u32 = ISB_MAGIC;

    fn inner_parse<E: ParseError<&'a [u8]>>(
        block_type: u32,
        block_len1: u32,
        i: &'a [u8],
        block_len2: u32,
    ) -> IResult<&'a [u8], InterfaceStatisticsBlock<'a>, E> {
        // caller function already tested header type(magic) and length
        // read end of header
        let (i, if_id) = En::parse_u32(i)?;
        let (i, ts_high) = En::parse_u32(i)?;
        let (i, ts_low) = En::parse_u32(i)?;
        // caller function already tested header type(magic) and length
        // read options
        let (i, options) = opt_parse_options::<En, E>(i, block_len1 as usize, 24)?;
        if block_len2 != block_len1 {
            return Err(Err::Error(E::from_error_kind(i, ErrorKind::Verify)));
        }
        let block = InterfaceStatisticsBlock {
            block_type,
            block_len1,
            if_id,
            ts_high,
            ts_low,
            options,
            block_len2,
        };
        Ok((i, block))
    }
}

/// Parse an InterfaceStatistics Block (little-endian)
#[inline]
pub fn parse_interfacestatisticsblock_le(
    i: &[u8],
) -> IResult<&[u8], InterfaceStatisticsBlock<'_>, PcapError<&[u8]>> {
    ng_block_parser::<InterfaceStatisticsBlock, PcapLE, _, _>()(i)
}

/// Parse an InterfaceStatistics Block (big-endian)
#[inline]
pub fn parse_interfacestatisticsblock_be(
    i: &[u8],
) -> IResult<&[u8], InterfaceStatisticsBlock<'_>, PcapError<&[u8]>> {
    ng_block_parser::<InterfaceStatisticsBlock, PcapBE, _, _>()(i)
}
