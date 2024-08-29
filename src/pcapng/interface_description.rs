use std::net::{Ipv4Addr, Ipv6Addr};

use nom::error::{ErrorKind, ParseError};
use nom::{Err, IResult};

use crate::endianness::{PcapBE, PcapEndianness, PcapLE};
use crate::{opt_parse_options, Linktype, PcapError, PcapNGOption, IDB_MAGIC};

use super::*;

/// An Interface Description Block (IDB) is the container for information
/// describing an interface on which packet data is captured.
#[derive(Debug)]
pub struct InterfaceDescriptionBlock<'a> {
    pub block_type: u32,
    pub block_len1: u32,
    pub linktype: Linktype,
    pub reserved: u16,
    pub snaplen: u32,
    pub options: Vec<PcapNGOption<'a>>,
    pub block_len2: u32,
    pub if_tsresol: u8,
    pub if_tsoffset: i64,
}

impl<'a> InterfaceDescriptionBlock<'a> {
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

    /// Return the `if_name` option value, if present
    ///
    /// If the option is present multiple times, the first value is returned.
    ///
    /// Returns `None` if option is not present, `Some(Ok(value))` if the value is present and valid,
    /// or `Some(Err(_))` if value is present but invalid
    pub fn if_name(&self) -> Option<Result<&str, PcapNGOptionError>> {
        options_get_as_str(&self.options, OptionCode::IfName)
    }

    /// Return the `if_description` option value, if present
    ///
    /// If the option is present multiple times, the first value is returned.
    ///
    /// Returns `None` if option is not present, `Some(Ok(value))` if the value is present and valid,
    /// or `Some(Err(_))` if value is present but invalid
    pub fn if_description(&self) -> Option<Result<&str, PcapNGOptionError>> {
        options_get_as_str(&self.options, OptionCode::IfDescription)
    }

    /// Return the `if_os` option value, if present
    ///
    /// If the option is present multiple times, the first value is returned.
    ///
    /// Returns `None` if option is not present, `Some(Ok(value))` if the value is present and valid,
    /// or `Some(Err(_))` if value is present but invalid
    pub fn if_os(&self) -> Option<Result<&str, PcapNGOptionError>> {
        options_get_as_str(&self.options, OptionCode::IfOs)
    }

    /// Return the `if_ipv4addr` option values, if present
    ///
    /// This option can be multi-valued.
    ///
    /// Returns `None` if option is not present, `Some(Ok(Vec))` if the value is present and valid,
    /// or `Some(Err(_))` if value is present but invalid
    ///
    /// Each item of the `Vec` is a pair `(IPv4Addr, IPv4Mask)`
    pub fn if_ipv4addr(&self) -> Option<Result<Vec<(Ipv4Addr, Ipv4Addr)>, PcapNGOptionError>> {
        let res = self.options.iter().try_fold(Vec::new(), |mut acc, opt| {
            if opt.code == OptionCode::IfIpv4Addr {
                let b = opt.as_bytes()?;
                if b.len() != 8 {
                    return Err(PcapNGOptionError::InvalidLength);
                }
                let addr = Ipv4Addr::new(b[0], b[1], b[2], b[3]);
                let mask = Ipv4Addr::new(b[4], b[5], b[6], b[7]);
                acc.push((addr, mask));
                Ok(acc)
            } else {
                Ok(acc)
            }
        });
        if res.as_ref().map_or(false, |v| v.is_empty()) {
            None
        } else {
            Some(res)
        }
    }

    /// Return the `if_ipv6addr` option values, if present
    ///
    /// This option can be multi-valued.
    ///
    /// Returns `None` if option is not present, `Some(Ok(Vec))` if the value is present and valid,
    /// or `Some(Err(_))` if value is present but invalid
    ///
    /// Each item of the `Vec` is a pair `(IPv6Addr, PrefixLen)`
    pub fn if_ipv6addr(&self) -> Option<Result<Vec<(Ipv6Addr, u8)>, PcapNGOptionError>> {
        let res = self.options.iter().try_fold(Vec::new(), |mut acc, opt| {
            if opt.code == OptionCode::IfIpv4Addr {
                let b = opt.as_bytes()?;
                if b.len() != 17 {
                    return Err(PcapNGOptionError::InvalidLength);
                }
                let mut array_u16 = [0u16; 8];
                for i in 0..8 {
                    array_u16[i] = ((b[2 * i] as u16) << 8) + b[2 * i + 1] as u16;
                }
                let addr = Ipv6Addr::new(
                    array_u16[0],
                    array_u16[1],
                    array_u16[2],
                    array_u16[3],
                    array_u16[4],
                    array_u16[5],
                    array_u16[6],
                    array_u16[7],
                );
                let mask = b[16];
                acc.push((addr, mask));
                Ok(acc)
            } else {
                Ok(acc)
            }
        });
        if res.as_ref().map_or(false, |v| v.is_empty()) {
            None
        } else {
            Some(res)
        }
    }

    /// Return the `if_macaddr` option value, if present
    ///
    /// If the option is present multiple times, the first value is returned.
    ///
    /// Returns `None` if option is not present, `Some(Ok(value))` if the value is present and valid,
    /// or `Some(Err(_))` if value is present but invalid
    pub fn if_macaddr(&self) -> Option<Result<&[u8], PcapNGOptionError>> {
        options_get_as_bytes(&self.options, OptionCode::IfMacAddr)
    }

    /// Return the `if_euiaddr` option value, if present
    ///
    /// If the option is present multiple times, the first value is returned.
    ///
    /// Returns `None` if option is not present, `Some(Ok(value))` if the value is present and valid,
    /// or `Some(Err(_))` if value is present but invalid
    pub fn if_euiaddr(&self) -> Option<Result<&[u8], PcapNGOptionError>> {
        options_get_as_bytes(&self.options, OptionCode::IfEuiAddr)
    }

    /// Return the `if_speed` option value, if present
    ///
    /// If the option is present multiple times, the first value is returned.
    ///
    /// Returns `None` if option is not present, `Some(Ok(value))` if the value is present and valid,
    /// or `Some(Err(_))` if value is present but invalid
    pub fn if_speed(&self) -> Option<Result<u64, PcapNGOptionError>> {
        options_get_as_u64_le(&self.options, OptionCode::IfSpeed)
    }

    /// Return the `if_tsresol` option value, if present
    ///
    /// If the option is present multiple times, the first value is returned.
    ///
    /// Returns `None` if option is not present, `Some(Ok(value))` if the value is present and valid,
    /// or `Some(Err(_))` if value is present but invalid
    pub fn if_tsresol(&self) -> Option<Result<u8, PcapNGOptionError>> {
        options_get_as_u8(&self.options, OptionCode::IfTsresol)
    }

    /// Return the `if_filter` option value, if present
    ///
    /// If the option is present multiple times, the first value is returned.
    ///
    /// Returns `None` if option is not present, `Some(Ok(value))` if the value is present and valid,
    /// or `Some(Err(_))` if value is present but invalid
    pub fn if_filter(&self) -> Option<Result<&str, PcapNGOptionError>> {
        options_get_as_str(&self.options, OptionCode::IfFilter)
    }

    /// Return the `if_tsoffset` option value, if present
    ///
    /// If the option is present multiple times, the first value is returned.
    ///
    /// Returns `None` if option is not present, `Some(Ok(value))` if the value is present and valid,
    /// or `Some(Err(_))` if value is present but invalid
    pub fn if_tsoffset(&self) -> Option<Result<i64, PcapNGOptionError>> {
        options_get_as_i64_le(&self.options, OptionCode::IfTsoffset)
    }
}

impl<'a, En: PcapEndianness> PcapNGBlockParser<'a, En, InterfaceDescriptionBlock<'a>>
    for InterfaceDescriptionBlock<'a>
{
    const HDR_SZ: usize = 20;
    const MAGIC: u32 = IDB_MAGIC;

    fn inner_parse<E: ParseError<&'a [u8]>>(
        block_type: u32,
        block_len1: u32,
        i: &'a [u8],
        block_len2: u32,
    ) -> IResult<&'a [u8], InterfaceDescriptionBlock<'a>, E> {
        // caller function already tested header type(magic) and length
        // read end of header
        let (i, linktype) = En::parse_u16(i)?;
        let (i, reserved) = En::parse_u16(i)?;
        let (i, snaplen) = En::parse_u32(i)?;
        // read options
        let (i, options) = opt_parse_options::<En, E>(i, block_len1 as usize, 20)?;
        if block_len2 != block_len1 {
            return Err(Err::Error(E::from_error_kind(i, ErrorKind::Verify)));
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
pub fn parse_interfacedescriptionblock_le(
    i: &[u8],
) -> IResult<&[u8], InterfaceDescriptionBlock, PcapError<&[u8]>> {
    ng_block_parser::<InterfaceDescriptionBlock, PcapLE, _, _>()(i)
}

/// Parse an Interface Packet Block (big-endian)
pub fn parse_interfacedescriptionblock_be(
    i: &[u8],
) -> IResult<&[u8], InterfaceDescriptionBlock, PcapError<&[u8]>> {
    ng_block_parser::<InterfaceDescriptionBlock, PcapBE, _, _>()(i)
}
