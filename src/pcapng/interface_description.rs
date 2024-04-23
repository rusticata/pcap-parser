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
