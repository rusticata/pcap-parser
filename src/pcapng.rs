//! PCAPNG file format
//!
//! See <https://github.com/pcapng/pcapng> for details.
//!
//! There are several ways of parsing a PCAPNG file. The first method is to use
//! [`parse_pcapng`](../fn.parse_pcapng.html). This method requires to load the entire
//! file to memory, and thus may not be good for large files.
//!
//! The second method is to create a [`PcapNGCapture`](../struct.PcapNGCapture.html) object,
//! which  implements the [`Capture`](../trait.Capture.html) trait to provide generic methods.
//! However, this method also reads the entire file.
//!
//! The third (and prefered) method is to use a [`PcapNGReader`](../struct.PcapNGReader.html)
//! object.
//!
//! The last method is to manually read the blocks using
//! [`parse_sectionheaderblock`](fn.parse_sectionheaderblock.html),
//! [`parse_block_le`](fn.parse_block_le.html) and/or
//! [`parse_block_be`](fn.parse_block_be.html).
//!
//! ## File format and parsing
//!
//! A capture file is organized in blocks. Blocks are organized in sections, each section
//! starting with a Section Header Block (SHB), and followed by blocks (interface description,
//! statistics, packets, etc.).
//! A file is usually composed of one section, but can contain multiple sections. When a SHB is
//! encountered, this means a new section starts (and all information about previous section has to
//! be flushed, like interfaces).
//!
//! ## Endianness
//!
//! The endianness of a block is indicated by the Section Header Block that started the section
//! containing this block. Since a file can contain several sections, a single file can contain
//! both endianness variants.

use crate::blocks::PcapBlock;
use crate::endianness::*;
use crate::error::PcapError;
use crate::traits::*;
use crate::utils::*;
use nom::bytes::streaming::take;
use nom::combinator::{complete, map, map_parser};
use nom::error::*;
use nom::multi::{many0, many1};
use nom::number::streaming::{be_u32, le_u32};
use nom::{Err, IResult};
use rusticata_macros::{align32, newtype_enum};
use std::borrow::Cow;
use std::convert::TryFrom;

mod custom;
mod decryption_secrets;
mod enhanced_packet;
mod interface_description;
mod interface_statistics;
mod name_resolution;
mod process_information;
mod section_header;
mod simple_packet;
mod systemd_journal_export;

pub use custom::*;
pub use decryption_secrets::*;
pub use enhanced_packet::*;
pub use interface_description::*;
pub use interface_statistics::*;
pub use name_resolution::*;
pub use process_information::*;
pub use section_header::*;
pub use simple_packet::*;
pub use systemd_journal_export::*;

trait PcapNGBlockParser<'a, En: PcapEndianness, O: 'a> {
    /// Minimum header size, in bytes
    const HDR_SZ: usize;
    /// Little-endian magic number for this block type
    const MAGIC: u32;

    // caller function must have tested header type(magic) and length
    fn inner_parse<E: ParseError<&'a [u8]>>(
        block_type: u32,
        block_len1: u32,
        i: &'a [u8],
        block_len2: u32,
    ) -> IResult<&'a [u8], O, E>;
}

/// Section Header Block magic
pub const SHB_MAGIC: u32 = 0x0A0D_0D0A;
/// Interface Description Block magic
pub const IDB_MAGIC: u32 = 0x0000_0001;
/// Simple Packet Block magic
pub const SPB_MAGIC: u32 = 0x0000_0003;
/// Name Resolution Block magic
pub const NRB_MAGIC: u32 = 0x0000_0004;
/// Interface Statistic Block magic
pub const ISB_MAGIC: u32 = 0x0000_0005;
/// Enhanced Packet Block magic
pub const EPB_MAGIC: u32 = 0x0000_0006;

/// Systemd Journal Export Block magic
pub const SJE_MAGIC: u32 = 0x0000_0009;

/// Decryption Secrets Block magic
pub const DSB_MAGIC: u32 = 0x0000_000A;

/// Custom Block magic
pub const CB_MAGIC: u32 = 0x0000_0BAD;

/// Do-not-copy Custom Block magic
pub const DCB_MAGIC: u32 = 0x4000_0BAD;

/// Byte Order magic
pub const BOM_MAGIC: u32 = 0x1A2B_3C4D;

/// Process Information Block magic
/// (Apple addition, non standardized)
pub const PIB_MAGIC: u32 = 0x8000_0001;

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct OptionCode(pub u16);

newtype_enum! {
impl debug OptionCode {
    EndOfOpt = 0,
    Comment = 1,
    ShbHardware = 2,
    ShbOs = 3,
    ShbUserAppl = 4,
    IfTsresol = 9,
    IfTsoffset = 14,
    Custom2988 = 2988,
    Custom2989 = 2989,
    Custom19372 = 19372,
    Custom19373 = 19373,
}
}

/// A block from a PcapNG file
#[derive(Debug)]
pub enum Block<'a> {
    SectionHeader(SectionHeaderBlock<'a>),
    InterfaceDescription(InterfaceDescriptionBlock<'a>),
    EnhancedPacket(EnhancedPacketBlock<'a>),
    SimplePacket(SimplePacketBlock<'a>),
    NameResolution(NameResolutionBlock<'a>),
    InterfaceStatistics(InterfaceStatisticsBlock<'a>),
    SystemdJournalExport(SystemdJournalExportBlock<'a>),
    DecryptionSecrets(DecryptionSecretsBlock<'a>),
    ProcessInformation(ProcessInformationBlock<'a>),
    Custom(CustomBlock<'a>),
    Unknown(UnknownBlock<'a>),
}

impl<'a> Block<'a> {
    /// Returns true if blocks contains a network packet
    pub fn is_data_block(&self) -> bool {
        matches!(self, &Block::EnhancedPacket(_) | &Block::SimplePacket(_))
    }

    /// Return the normalized magic number of the block
    pub fn magic(&self) -> u32 {
        match self {
            Block::SectionHeader(_) => SHB_MAGIC,
            Block::InterfaceDescription(_) => IDB_MAGIC,
            Block::EnhancedPacket(_) => EPB_MAGIC,
            Block::SimplePacket(_) => SPB_MAGIC,
            Block::NameResolution(_) => NRB_MAGIC,
            Block::InterfaceStatistics(_) => ISB_MAGIC,
            Block::SystemdJournalExport(_) => SJE_MAGIC,
            Block::DecryptionSecrets(_) => DSB_MAGIC,
            Block::ProcessInformation(_) => PIB_MAGIC,
            Block::Custom(cb) => cb.block_type,
            Block::Unknown(ub) => ub.block_type,
        }
    }
}

/// A Section (including all blocks) from a PcapNG file
pub struct Section<'a> {
    /// The list of blocks
    pub blocks: Vec<Block<'a>>,
    /// True if encoding is big-endian
    pub big_endian: bool,
}

impl<'a> Section<'a> {
    /// Returns the section header
    pub fn header(&self) -> Option<&SectionHeaderBlock> {
        if let Some(Block::SectionHeader(ref b)) = self.blocks.first() {
            Some(b)
        } else {
            None
        }
    }

    /// Returns an iterator over the section blocks
    pub fn iter(&'a self) -> SectionBlockIterator<'a> {
        SectionBlockIterator {
            section: self,
            index_block: 0,
        }
    }

    /// Returns an iterator over the interface description blocks
    pub fn iter_interfaces(&'a self) -> InterfaceBlockIterator<'a> {
        InterfaceBlockIterator {
            section: self,
            index_block: 0,
        }
    }
}

// Non-consuming iterator over blocks of a Section
pub struct SectionBlockIterator<'a> {
    section: &'a Section<'a>,
    index_block: usize,
}

impl<'a> Iterator for SectionBlockIterator<'a> {
    type Item = PcapBlock<'a>;

    fn next(&mut self) -> Option<PcapBlock<'a>> {
        let block = self.section.blocks.get(self.index_block);
        self.index_block += 1;
        block.map(PcapBlock::from)
    }
}

// Non-consuming iterator over interface description blocks of a Section
pub struct InterfaceBlockIterator<'a> {
    section: &'a Section<'a>,
    index_block: usize,
}

impl<'a> Iterator for InterfaceBlockIterator<'a> {
    type Item = &'a InterfaceDescriptionBlock<'a>;

    fn next(&mut self) -> Option<&'a InterfaceDescriptionBlock<'a>> {
        if self.index_block >= self.section.blocks.len() {
            return None;
        }
        for block in &self.section.blocks[self.index_block..] {
            self.index_block += 1;
            if let Block::InterfaceDescription(ref idb) = block {
                return Some(idb);
            }
        }
        None
    }
}

/// Compute the timestamp resolution, in units per second
///
/// Return the resolution, or `None` if the resolution is invalid (for ex. greater than `2^64`)
pub fn build_ts_resolution(ts_resol: u8) -> Option<u64> {
    let ts_mode = ts_resol & 0x80;
    let unit = if ts_mode == 0 {
        // 10^if_tsresol
        // check that if_tsresol <= 19 (10^19 is the largest power of 10 to fit in a u64)
        if ts_resol > 19 {
            return None;
        }
        10u64.pow(ts_resol as u32)
    } else {
        // 2^if_tsresol
        // check that if_tsresol <= 63
        if ts_resol > 63 {
            return None;
        }
        1 << ((ts_resol & 0x7f) as u64)
    };
    Some(unit)
}

/// Given the timestamp parameters, return the timestamp seconds and fractional part (in resolution
/// units)
pub fn build_ts(ts_high: u32, ts_low: u32, ts_offset: u64, resolution: u64) -> (u32, u32) {
    let if_tsoffset = ts_offset;
    let ts: u64 = ((ts_high as u64) << 32) | (ts_low as u64);
    let ts_sec = (if_tsoffset + (ts / resolution)) as u32;
    let ts_fractional = (ts % resolution) as u32;
    (ts_sec, ts_fractional)
}

/// Given the timestamp parameters, return the timestamp as a `f64` value.
///
/// The resolution is given in units per second. In pcap-ng files, it is stored in the
/// Interface Description Block, and can be obtained using [`InterfaceDescriptionBlock::ts_resolution`]
pub fn build_ts_f64(ts_high: u32, ts_low: u32, ts_offset: u64, resolution: u64) -> f64 {
    let ts: u64 = ((ts_high as u64) << 32) | (ts_low as u64);
    let ts_sec = (ts_offset + (ts / resolution)) as u32;
    let ts_fractional = (ts % resolution) as u32;
    // XXX should we round to closest unit?
    ts_sec as f64 + ((ts_fractional as f64) / (resolution as f64))
}

/// Unknown block (magic not recognized, or not yet implemented)
#[derive(Debug)]
pub struct UnknownBlock<'a> {
    /// Block type (little endian)
    pub block_type: u32,
    pub block_len1: u32,
    pub data: &'a [u8],
    pub block_len2: u32,
}

impl<'a, En: PcapEndianness> PcapNGBlockParser<'a, En, UnknownBlock<'a>> for UnknownBlock<'a> {
    const HDR_SZ: usize = 12;
    const MAGIC: u32 = 0;

    fn inner_parse<E: ParseError<&'a [u8]>>(
        block_type: u32,
        block_len1: u32,
        i: &'a [u8],
        block_len2: u32,
    ) -> IResult<&'a [u8], UnknownBlock<'a>, E> {
        let block = UnknownBlock {
            block_type,
            block_len1,
            data: i,
            block_len2,
        };
        Ok((i, block))
    }
}

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
    pub fn as_bytes(&self) -> Option<&[u8]> {
        let len = usize::from(self.len);
        if len <= self.value.len() {
            Some(&self.value[..len])
        } else {
            None
        }
    }

    /// Return the option value interpreted as i32, or None
    ///
    /// Option data length and declared must be exactly 4 bytes
    pub fn as_i32_le(&self) -> Option<i32> {
        if self.len == 8 && self.value.len() == 8 {
            <[u8; 4]>::try_from(self.value())
                .ok()
                .map(i32::from_le_bytes)
        } else {
            None
        }
    }

    /// Return the option value interpreted as u32, or None
    ///
    /// Option data length and declared must be exactly 4 bytes
    pub fn as_u32_le(&self) -> Option<u32> {
        if self.len == 8 && self.value.len() == 8 {
            <[u8; 4]>::try_from(self.value())
                .ok()
                .map(u32::from_le_bytes)
        } else {
            None
        }
    }

    /// Return the option value interpreted as i64, or None
    ///
    /// Option data length and declared must be exactly 8 bytes
    pub fn as_i64_le(&self) -> Option<i64> {
        if self.len == 8 && self.value.len() == 8 {
            <[u8; 8]>::try_from(self.value())
                .ok()
                .map(i64::from_le_bytes)
        } else {
            None
        }
    }

    /// Return the option value interpreted as u64, or None
    ///
    /// Option data length and declared must be exactly 8 bytes
    pub fn as_u64_le(&self) -> Option<u64> {
        if self.len == 8 && self.value.len() == 8 {
            <[u8; 8]>::try_from(self.value())
                .ok()
                .map(u64::from_le_bytes)
        } else {
            None
        }
    }
}

#[derive(Debug)]
pub struct PcapNGHeader {
    pub magic_number: u32,
    pub version_major: u16,
    pub version_minor: u16,
    pub thiszone: i32,
    pub sigfigs: u32,
    /// max len of captured packets, in octets
    pub snaplen: u32,
    /// Data link type
    pub network: u32,
}

/// Create a block parser function, given the parameters (block object and endianness)
fn ng_block_parser<'a, P, En, O, E>() -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], O, E>
where
    P: PcapNGBlockParser<'a, En, O>,
    En: PcapEndianness,
    O: 'a,
    E: ParseError<&'a [u8]>,
{
    move |i: &[u8]| {
        // read generic block layout
        //
        if i.len() < P::HDR_SZ {
            return Err(Err::Incomplete(nom::Needed::new(P::HDR_SZ - i.len())));
        }
        let (i, block_type) = le_u32(i)?;
        let (i, block_len1) = En::parse_u32(i)?;
        if block_len1 < P::HDR_SZ as u32 {
            return Err(Err::Error(E::from_error_kind(i, ErrorKind::Verify)));
        }
        if P::MAGIC != 0 && En::native_u32(block_type) != P::MAGIC {
            return Err(Err::Error(E::from_error_kind(i, ErrorKind::Verify)));
        }
        // 12 is block_type (4) + block_len1 (4) + block_len2 (4)
        let (i, block_content) = take(block_len1 - 12)(i)?;
        let (i, block_len2) = En::parse_u32(i)?;
        // call block content parsing function
        let (_, b) = P::inner_parse(block_type, block_len1, block_content, block_len2)?;
        // return the remaining bytes from the container, not content
        Ok((i, b))
    }
}

#[inline]
pub fn parse_option_le<'i, E: ParseError<&'i [u8]>>(
    i: &'i [u8],
) -> IResult<&'i [u8], PcapNGOption, E> {
    parse_option::<PcapLE, E>(i)
}

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

fn if_extract_tsoffset_and_tsresol(options: &[PcapNGOption]) -> (u8, i64) {
    let mut if_tsresol: u8 = 6;
    let mut if_tsoffset: i64 = 0;
    for opt in options {
        match opt.code {
            OptionCode::IfTsresol => {
                if !opt.value.is_empty() {
                    if_tsresol = opt.value[0];
                }
            }
            OptionCode::IfTsoffset => {
                if opt.value.len() >= 8 {
                    let int_bytes =
                        <[u8; 8]>::try_from(&opt.value[..8]).expect("Convert bytes to i64");
                    if_tsoffset = i64::from_le_bytes(int_bytes);
                }
            }
            _ => (),
        }
    }
    (if_tsresol, if_tsoffset)
}

/// Parse an unknown block (little-endian)
pub fn parse_unknownblock_le(i: &[u8]) -> IResult<&[u8], UnknownBlock, PcapError<&[u8]>> {
    ng_block_parser::<UnknownBlock, PcapLE, _, _>()(i)
}

/// Parse an unknown block (big-endian)
pub fn parse_unknownblock_be(i: &[u8]) -> IResult<&[u8], UnknownBlock, PcapError<&[u8]>> {
    ng_block_parser::<UnknownBlock, PcapBE, _, _>()(i)
}

/// Parse any block, as little-endian
///
/// To find which endianess to use, read the section header
/// using `parse_sectionheaderblock`
pub fn parse_block_le(i: &[u8]) -> IResult<&[u8], Block, PcapError<&[u8]>> {
    match le_u32(i) {
        Ok((_, id)) => match id {
            SHB_MAGIC => map(parse_sectionheaderblock, Block::SectionHeader)(i),
            IDB_MAGIC => map(
                parse_interfacedescriptionblock_le,
                Block::InterfaceDescription,
            )(i),
            SPB_MAGIC => map(parse_simplepacketblock_le, Block::SimplePacket)(i),
            EPB_MAGIC => map(parse_enhancedpacketblock_le, Block::EnhancedPacket)(i),
            NRB_MAGIC => map(parse_nameresolutionblock_le, Block::NameResolution)(i),
            ISB_MAGIC => map(
                parse_interfacestatisticsblock_le,
                Block::InterfaceStatistics,
            )(i),
            SJE_MAGIC => map(
                parse_systemdjournalexportblock_le,
                Block::SystemdJournalExport,
            )(i),
            DSB_MAGIC => map(parse_decryptionsecretsblock_le, Block::DecryptionSecrets)(i),
            CB_MAGIC => map(parse_customblock_le, Block::Custom)(i),
            DCB_MAGIC => map(parse_dcb_le, Block::Custom)(i),
            PIB_MAGIC => map(parse_processinformationblock_le, Block::ProcessInformation)(i),
            _ => map(parse_unknownblock_le, Block::Unknown)(i),
        },
        Err(e) => Err(e),
    }
}

/// Parse any block, as big-endian
///
/// To find which endianess to use, read the section header
/// using `parse_sectionheaderblock`
pub fn parse_block_be(i: &[u8]) -> IResult<&[u8], Block, PcapError<&[u8]>> {
    match be_u32(i) {
        Ok((_, id)) => match id {
            SHB_MAGIC => map(parse_sectionheaderblock, Block::SectionHeader)(i),
            IDB_MAGIC => map(
                parse_interfacedescriptionblock_be,
                Block::InterfaceDescription,
            )(i),
            SPB_MAGIC => map(parse_simplepacketblock_be, Block::SimplePacket)(i),
            EPB_MAGIC => map(parse_enhancedpacketblock_be, Block::EnhancedPacket)(i),
            NRB_MAGIC => map(parse_nameresolutionblock_be, Block::NameResolution)(i),
            ISB_MAGIC => map(
                parse_interfacestatisticsblock_be,
                Block::InterfaceStatistics,
            )(i),
            SJE_MAGIC => map(
                parse_systemdjournalexportblock_be,
                Block::SystemdJournalExport,
            )(i),
            DSB_MAGIC => map(parse_decryptionsecretsblock_be, Block::DecryptionSecrets)(i),
            CB_MAGIC => map(parse_customblock_be, Block::Custom)(i),
            DCB_MAGIC => map(parse_dcb_be, Block::Custom)(i),
            PIB_MAGIC => map(parse_processinformationblock_be, Block::ProcessInformation)(i),
            _ => map(parse_unknownblock_be, Block::Unknown)(i),
        },
        Err(e) => Err(e),
    }
}

/// Parse any block from a section (little-endian)
pub fn parse_section_content_block_le(i: &[u8]) -> IResult<&[u8], Block, PcapError<&[u8]>> {
    let (rem, block) = parse_block_le(i)?;
    match block {
        Block::SectionHeader(_) => Err(Err::Error(make_error(i, ErrorKind::Tag))),
        _ => Ok((rem, block)),
    }
}

/// Parse any block from a section (big-endian)
pub fn parse_section_content_block_be(i: &[u8]) -> IResult<&[u8], Block, PcapError<&[u8]>> {
    let (rem, block) = parse_block_be(i)?;
    match block {
        Block::SectionHeader(_) => Err(Err::Error(make_error(i, ErrorKind::Tag))),
        _ => Ok((rem, block)),
    }
}

/// Parse one section (little or big endian)
pub fn parse_section(i: &[u8]) -> IResult<&[u8], Section, PcapError<&[u8]>> {
    let (rem, shb) = parse_sectionheaderblock(i)?;
    let big_endian = shb.big_endian();
    let (rem, mut b) = if big_endian {
        many0(complete(parse_section_content_block_be))(rem)?
    } else {
        many0(complete(parse_section_content_block_le))(rem)?
    };
    let mut blocks = Vec::with_capacity(b.len() + 1);
    blocks.push(Block::SectionHeader(shb));
    blocks.append(&mut b);
    let section = Section { blocks, big_endian };
    Ok((rem, section))
}

/// Parse multiple sections (little or big endian)
#[inline]
pub fn parse_sections(i: &[u8]) -> IResult<&[u8], Vec<Section>, PcapError<&[u8]>> {
    many1(complete(parse_section))(i)
}
