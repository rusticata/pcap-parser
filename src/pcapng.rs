//! PCAPNG file format
//!
//! See [https://github.com/pcapng/pcapng](https://github.com/pcapng/pcapng) for details.
//!
//! There are 2 main ways of parsing a PCAPNG file. The first method is to use
//! [`parse_pcapng`](fn.parse_pcapng.html). This method requires to load the entire
//! file to memory, and thus may not be good for large files.
//!
//! The [`PcapNGCapture`](struct.PcapNGCapture.html) implements the
//! [`Capture`](../trait.Capture.html) trait to provide generic methods. However,
//! this trait also reads the entire file.
//!
//! The second method is to loop over [`parse_block`](fn.parse_block.html) and match the
//! result. The first block should be a Section header, then there should be one or more
//! interfaces, etc.
//! This can be used in a streaming parser.

use crate::blocks::PcapBlock;
use crate::error::PcapError;
use crate::linktype::Linktype;
use nom::bytes::complete::take;
use nom::combinator::{complete, map_parser, rest};
use nom::error::*;
use nom::multi::many0;
use nom::number::streaming::{be_i64, be_u16, be_u32, le_i64, le_u16, le_u32};
use nom::{Err, IResult};
use rusticata_macros::{align32, q};
use std::convert::TryFrom;

/// Section Header Block magic
pub const SHB_MAGIC: u32 = 0x0A0D0D0A;
/// Interface Description Block magic
pub const IDB_MAGIC: u32 = 0x00000001;
/// Simple Packet Block magic
pub const SPB_MAGIC: u32 = 0x00000003;
/// Name Resolution Block magic
pub const NRB_MAGIC: u32 = 0x00000004;
/// Interface Statistic Block magic
pub const ISB_MAGIC: u32 = 0x00000005;
/// Enhanced Packet Block magic
pub const EPB_MAGIC: u32 = 0x00000006;

/// Custom Block magic
pub const CB_MAGIC: u32 = 0x00000BAD;

/// Do-not-copy Custom Block magic
pub const DCB_MAGIC: u32 = 0x40000BAD;

/// Byte Order magic
pub const BOM_MAGIC: u32 = 0x1A2B3C4D;

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
pub enum Block<'a> {
    SectionHeader(SectionHeaderBlock<'a>),
    InterfaceDescription(InterfaceDescriptionBlock<'a>),
    EnhancedPacket(EnhancedPacketBlock<'a>),
    SimplePacket(SimplePacketBlock<'a>),
    NameResolution(NameResolutionBlock<'a>),
    InterfaceStatistics(InterfaceStatisticsBlock<'a>),
    Custom(CustomBlock<'a>),
    Unknown(UnknownBlock<'a>),
}

impl<'a> Block<'a> {
    /// Returns true if blocks contains a network packet
    pub fn is_data_block(&self) -> bool {
        match self {
            &Block::EnhancedPacket(_) | &Block::SimplePacket(_) => true,
            _ => false,
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
    pub fn header<'section>(&'section self) -> Option<&'section SectionHeaderBlock<'section>> {
        if let Some(Block::SectionHeader(ref b)) = self.blocks.get(0) {
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
        block.map(|b| PcapBlock::from(b))
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

/// Given the timestamp parameters, return the timestamp seconds, fractional part and precision
/// (unit) of the fractional part.
pub fn build_ts(ts_high: u32, ts_low: u32, ts_offset: u64, ts_resol: u8) -> (u32, u32, u64) {
    let if_tsoffset = ts_offset;
    let if_tsresol = ts_resol;
    let ts_mode = if_tsresol & 0x70;
    let unit = if ts_mode == 0 {
        10u64.pow(if_tsresol as u32)
    } else {
        2u64.pow((if_tsresol & !0x70) as u32)
    };
    let ts: u64 = ((ts_high as u64) << 32) | (ts_low as u64);
    let ts_sec = (if_tsoffset + (ts / unit)) as u32;
    let ts_fractional = (ts % unit) as u32;
    (ts_sec, ts_fractional, unit)
}

#[derive(Debug)]
pub struct SectionHeaderBlock<'a> {
    pub block_type: u32,
    pub block_len1: u32,
    /// Byte-order magic
    pub bom: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub section_len: i64,
    pub options: Vec<PcapNGOption<'a>>,
    pub block_len2: u32,
}

impl<'a> SectionHeaderBlock<'a> {
    pub fn is_bigendian(&self) -> bool {
        self.bom != BOM_MAGIC
    }
}

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
    pub if_tsoffset: u64,
}

pub struct EnhancedPacketBlock<'a> {
    pub block_type: u32,
    pub block_len1: u32,
    pub if_id: u32,
    pub ts_high: u32,
    pub ts_low: u32,
    /// Captured packet length
    pub caplen: u32,
    /// Original packet length
    pub origlen: u32,
    pub data: &'a [u8],
    pub options: Vec<PcapNGOption<'a>>,
    pub block_len2: u32,
}

pub struct SimplePacketBlock<'a> {
    pub block_type: u32,
    pub block_len1: u32,
    /// Original packet length
    pub origlen: u32,
    pub data: &'a [u8],
    pub block_len2: u32,
}

pub struct NameRecord<'a> {
    pub record_type: u16,
    pub record_value: &'a [u8],
}

pub struct NameResolutionBlock<'a> {
    pub block_type: u32,
    pub block_len1: u32,
    pub nr: Vec<NameRecord<'a>>,
    pub opt: &'a [u8],
    pub block_len2: u32,
}

pub struct InterfaceStatisticsBlock<'a> {
    pub block_type: u32,
    pub block_len1: u32,
    pub if_id: u32,
    pub ts_high: u32,
    pub ts_low: u32,
    pub options: Vec<PcapNGOption<'a>>,
    pub block_len2: u32,
}

pub struct CustomBlock<'a> {
    pub block_type: u32,
    pub block_len1: u32,
    // Private Enterprise Number (PEN)
    pub pen: u32,
    pub data: &'a [u8],
    // pub options: &'a [u8],
    pub block_len2: u32,
}

impl<'a> CustomBlock<'a> {
    pub fn do_not_copy(&self) -> bool {
        self.block_type == DCB_MAGIC
    }
}

pub struct UnknownBlock<'a> {
    pub block_type: u32,
    pub block_len1: u32,
    pub data: &'a [u8],
    pub block_len2: u32,
}

#[derive(Debug)]
pub struct PcapNGOption<'a> {
    pub code: OptionCode,
    pub len: u16,
    pub value: &'a [u8],
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

pub fn parse_option<'i, E: ParseError<&'i [u8]>>(
    i: &'i [u8],
) -> IResult<&'i [u8], PcapNGOption, E> {
    do_parse! {
        i,
        code:  le_u16 >>
        len:   le_u16 >>
        value: take!(align32!(len as u32)) >>
        (
            PcapNGOption {
                code: OptionCode(code),
                len,
                value,
            }
        )
    }
}

pub fn parse_option_be<'i, E: ParseError<&'i [u8]>>(
    i: &'i [u8],
) -> IResult<&'i [u8], PcapNGOption, E> {
    do_parse! {
        i,
        code:  be_u16 >>
        len:   be_u16 >>
        value: take!(align32!(len as u32)) >>
        (
            PcapNGOption {
                code: OptionCode(code),
                len,
                value,
            }
        )
    }
}

fn opt_parse_options<'i>(
    i: &'i [u8],
    len: usize,
    opt_offset: usize,
) -> IResult<&'i [u8], Vec<PcapNGOption<'i>>, PcapError> {
    if len > opt_offset {
        map_parser(take(len - opt_offset), many0(complete(parse_option)))(i)
    } else {
        Ok((i, Vec::new()))
    }
}

fn opt_parse_options_be<'i>(
    i: &'i [u8],
    len: usize,
    opt_offset: usize,
) -> IResult<&'i [u8], Vec<PcapNGOption<'i>>, PcapError> {
    if len > opt_offset {
        map_parser(take(len - opt_offset), many0(complete(parse_option_be)))(i)
    } else {
        Ok((i, Vec::new()))
    }
}

pub fn parse_sectionheaderblock_le(i: &[u8]) -> IResult<&[u8], SectionHeaderBlock, PcapError> {
    do_parse! {
        i,
        block_type:    verify!(le_u32, |x:&u32| *x == SHB_MAGIC) >>
        block_len1:    le_u32 >>
        bom:           verify!(le_u32, |x:&u32| *x == BOM_MAGIC) >>
        major_version: le_u16 >>
        minor_version: le_u16 >>
        section_len:   le_i64 >>
        options:       call!(opt_parse_options, block_len1 as usize, 28) >>
        block_len2:    verify!(le_u32, |x:&u32| *x == block_len1) >>
        (
            SectionHeaderBlock{
                block_type,
                block_len1,
                bom,
                major_version,
                minor_version,
                section_len,
                options,
                block_len2,
            }
        )
    }
}

pub fn parse_sectionheaderblock_be(i: &[u8]) -> IResult<&[u8], SectionHeaderBlock, PcapError> {
    do_parse! {
        i,
        block_type:    verify!(be_u32, |x:&u32| *x == SHB_MAGIC) >>
        block_len1:    be_u32 >>
        bom:           le_u32 >>
        major_version: be_u16 >>
        minor_version: be_u16 >>
        section_len:   be_i64 >>
        options:       call!(opt_parse_options_be, block_len1 as usize, 28) >>
        block_len2:    verify!(be_u32, |x:&u32| *x == block_len1) >>
        (
            SectionHeaderBlock{
                block_type,
                block_len1,
                bom,
                major_version,
                minor_version,
                section_len,
                options,
                block_len2,
            }
        )
    }
}

pub fn parse_sectionheaderblock(i: &[u8]) -> IResult<&[u8], SectionHeaderBlock, PcapError> {
    let (_, (_, bom)) = peek!(i, tuple!(take!(8), le_u32))?;
    if bom == BOM_MAGIC {
        parse_sectionheaderblock_le(i)
    } else if bom == u32::from_be(BOM_MAGIC) {
        parse_sectionheaderblock_be(i)
    } else {
        Err(Err::Error(PcapError::HeaderNotRecognized))
    }
}

#[inline]
pub fn parse_sectionheader(i: &[u8]) -> IResult<&[u8], Block, PcapError> {
    parse_sectionheaderblock(i).map(|(r, b)| (r, Block::SectionHeader(b)))
}

fn if_extract_tsoffset_and_tsresol(options: &[PcapNGOption]) -> (u8, u64) {
    let mut if_tsresol: u8 = 6;
    let mut if_tsoffset: u64 = 0;
    for opt in options {
        match opt.code {
            OptionCode::IfTsresol => {
                if !opt.value.is_empty() {
                    if_tsresol = opt.value[0];
                }
            }
            OptionCode::IfTsoffset => {
                if opt.value.len() >= 8 {
                    let int_bytes = <[u8; 8]>::try_from(opt.value).expect("Convert bytes to u64");
                    if_tsoffset = u64::from_le_bytes(int_bytes);
                }
            }
            _ => (),
        }
    }
    (if_tsresol, if_tsoffset)
}

fn inner_parse_interfacedescription(
    i: &[u8],
    big_endian: bool,
) -> IResult<&[u8], InterfaceDescriptionBlock, PcapError> {
    let read_u16 = if big_endian { be_u16 } else { le_u16 };
    let read_u32 = if big_endian { be_u32 } else { le_u32 };
    let read_options = if big_endian {
        opt_parse_options_be
    } else {
        opt_parse_options
    };
    do_parse! {
        i,
        magic:      verify!(read_u32, |x:&u32| *x == IDB_MAGIC) >>
        block_len1: read_u32 >>
        linktype:   read_u16 >>
        reserved:   read_u16 >>
        snaplen:    read_u32 >>
        options:    call!(read_options, block_len1 as usize, 20) >>
        block_len2: verify!(read_u32, |x:&u32| *x == block_len1) >>
        ({
            let (if_tsresol, if_tsoffset) = if_extract_tsoffset_and_tsresol(&options);
            InterfaceDescriptionBlock{
                block_type: magic,
                block_len1,
                linktype: Linktype(linktype as i32),
                reserved,
                snaplen,
                options,
                block_len2,
                if_tsresol,
                if_tsoffset,
            }
        })
    }
}

#[inline]
pub fn parse_interfacedescription(
    i: &[u8],
) -> IResult<&[u8], InterfaceDescriptionBlock, PcapError> {
    inner_parse_interfacedescription(i, false)
}

#[inline]
pub fn parse_interfacedescription_be(
    i: &[u8],
) -> IResult<&[u8], InterfaceDescriptionBlock, PcapError> {
    inner_parse_interfacedescription(i, true)
}
#[inline]
pub fn parse_interfacedescriptionblock(i: &[u8]) -> IResult<&[u8], Block, PcapError> {
    parse_interfacedescription(i).map(|(r, b)| (r, Block::InterfaceDescription(b)))
}

#[inline]
pub fn parse_interfacedescriptionblock_be(i: &[u8]) -> IResult<&[u8], Block, PcapError> {
    parse_interfacedescription_be(i).map(|(r, b)| (r, Block::InterfaceDescription(b)))
}

fn inner_parse_simplepacketblock(i: &[u8], big_endian: bool) -> IResult<&[u8], Block, PcapError> {
    let read_u32 = if big_endian { be_u32 } else { le_u32 };
    do_parse! {
        i,
        magic:     verify!(read_u32, |x:&u32| *x == SPB_MAGIC) >>
        len1:      verify!(read_u32, |val:&u32| *val >= 32) >>
        origlen:   le_u32 >>
        // XXX if snaplen is < origlen, we MUST use snaplen
        // al_len:    value!(align32!(origlen)) >>
        // data:      take!(al_len) >>
        data:      take!(len1 - 16) >>
        len2:      verify!(read_u32, |x:&u32| *x == len1) >>
        (
            Block::SimplePacket(SimplePacketBlock{
                block_type: magic,
                block_len1: len1,
                origlen: origlen,
                data: data,
                block_len2: len2
            })
        )
    }
}

/// Parse a Simple Packet Block
///
/// *Note: this function does not remove padding*
#[inline]
pub fn parse_simplepacketblock(i: &[u8]) -> IResult<&[u8], Block, PcapError> {
    inner_parse_simplepacketblock(i, false)
}

/// Parse a Simple Packet Block (big-endian)
///
/// *Note: this function does not remove padding*
#[inline]
pub fn parse_simplepacketblock_be(i: &[u8]) -> IResult<&[u8], Block, PcapError> {
    inner_parse_simplepacketblock(i, true)
}

fn inner_parse_enhancedpacketblock(i: &[u8], big_endian: bool) -> IResult<&[u8], Block, PcapError> {
    let read_u32 = if big_endian { be_u32 } else { le_u32 };
    let read_options = if big_endian {
        opt_parse_options_be
    } else {
        opt_parse_options
    };
    do_parse! {
        i,
                    verify!(read_u32, |x:&u32| *x == EPB_MAGIC) >>
        block_len1: verify!(read_u32, |val:&u32| *val >= 32) >>
        if_id:      read_u32 >>
        ts_high:    read_u32 >>
        ts_low:     read_u32 >>
        caplen:     verify!(read_u32, |x| *x < ::std::u32::MAX - 4) >>
        origlen:    read_u32 >>
        al_len:     q!(align32!(caplen) as usize) >>
        data:       take!(al_len) >>
        options:    call!(read_options, block_len1 as usize, 32 + al_len) >>
        block_len2: verify!(read_u32, |x:&u32| *x == block_len1) >>
        ({
            Block::EnhancedPacket(EnhancedPacketBlock{
                block_type: EPB_MAGIC,
                block_len1,
                if_id,
                ts_high,
                ts_low,
                caplen,
                origlen,
                data,
                options,
                block_len2,
            })
        })
    }
}

#[inline]
pub fn parse_enhancedpacketblock(i: &[u8]) -> IResult<&[u8], Block, PcapError> {
    inner_parse_enhancedpacketblock(i, false)
}

#[inline]
pub fn parse_enhancedpacketblock_be(i: &[u8]) -> IResult<&[u8], Block, PcapError> {
    inner_parse_enhancedpacketblock(i, true)
}

fn parse_name_record(i: &[u8], big_endian: bool) -> IResult<&[u8], NameRecord, PcapError> {
    let read_u16 = if big_endian { be_u16 } else { le_u16 };
    do_parse! {
        i,
        record_type: read_u16 >>
        record_len: verify!(read_u16, |x| *x < ::std::u16::MAX - 4) >>
        record_value: take!(align32!(record_len)) >>
        (
            NameRecord{
                record_type,
                record_value,
            }
        )
    }
}

fn parse_name_record_list(
    i: &[u8],
    big_endian: bool,
) -> IResult<&[u8], Vec<NameRecord>, PcapError> {
    many_till!(
        i,
        call!(parse_name_record, big_endian),
        verify!(le_u32, |x: &u32| *x == 0)
    )
    .map(|(rem, (v, _))| (rem, v))
}

fn inner_parse_nameresolutionblock(i: &[u8], big_endian: bool) -> IResult<&[u8], Block, PcapError> {
    let read_u32 = if big_endian { be_u32 } else { le_u32 };
    do_parse! {
        i,
                    verify!(read_u32, |x:&u32| *x == NRB_MAGIC) >>
        len1:       verify!(read_u32, |val:&u32| *val >= 16) >>
        nr_and_opt: flat_map!(
            take!(len1 - 12),
            tuple!(call!(parse_name_record_list, big_endian), rest)
            ) >>
        len2:       verify!(read_u32, |x:&u32| *x == len1) >>
        ({
            Block::NameResolution(NameResolutionBlock{
                block_type: EPB_MAGIC,
                block_len1: len1,
                nr: nr_and_opt.0,
                opt: nr_and_opt.1,
                block_len2: len2
            })
        })
    }
}

#[inline]
pub fn parse_nameresolutionblock(i: &[u8]) -> IResult<&[u8], Block, PcapError> {
    inner_parse_nameresolutionblock(i, false)
}

#[inline]
pub fn parse_nameresolutionblock_be(i: &[u8]) -> IResult<&[u8], Block, PcapError> {
    inner_parse_nameresolutionblock(i, true)
}

pub fn parse_interfacestatisticsblock(i: &[u8]) -> IResult<&[u8], Block, PcapError> {
    do_parse! {
        i,
        magic:      verify!(le_u32, |x:&u32| *x == ISB_MAGIC) >>
        block_len1: le_u32 >>
        if_id:      le_u32 >>
        ts_high:    le_u32 >>
        ts_low:     le_u32 >>
        options:    call!(opt_parse_options, block_len1 as usize, 24) >>
        block_len2: verify!(le_u32, |x:&u32| *x == block_len1) >>
        (
            Block::InterfaceStatistics(InterfaceStatisticsBlock{
                block_type: magic,
                block_len1,
                if_id,
                ts_high,
                ts_low,
                options,
                block_len2,
            })
        )
    }
}

pub fn parse_interfacestatisticsblock_be(i: &[u8]) -> IResult<&[u8], Block, PcapError> {
    do_parse! {
        i,
        magic:      verify!(be_u32, |x:&u32| *x == ISB_MAGIC) >>
        block_len1: be_u32 >>
        if_id:      be_u32 >>
        ts_high:    be_u32 >>
        ts_low:     be_u32 >>
        options:    call!(opt_parse_options_be, block_len1 as usize, 24) >>
        block_len2: verify!(be_u32, |x:&u32| *x == block_len1) >>
        (
            Block::InterfaceStatistics(InterfaceStatisticsBlock{
                block_type: magic,
                block_len1,
                if_id,
                ts_high,
                ts_low,
                options,
                block_len2,
            })
        )
    }
}

fn inner_parse_customblock(i: &[u8], big_endian: bool) -> IResult<&[u8], Block, PcapError> {
    let read_u32 = if big_endian { be_u32 } else { le_u32 };
    do_parse! {
        i,
        blocktype: read_u32 >>
        len1:      verify!(read_u32, |val: &u32| *val >= 16) >>
        pen:       read_u32 >>
        data:      take!(len1 - 16) >>
        // options cannot be parsed, we don't know the length of data
        len2:      verify!(read_u32, |x: &u32| *x == len1) >>
        (
            Block::Custom(CustomBlock {
                block_type: blocktype,
                block_len1: len1,
                pen,
                data,
                block_len2: len2
            })
        )
    }
}

#[inline]
pub fn parse_customblock(i: &[u8]) -> IResult<&[u8], Block, PcapError> {
    inner_parse_customblock(i, false)
}

#[inline]
pub fn parse_customblock_be(i: &[u8]) -> IResult<&[u8], Block, PcapError> {
    inner_parse_customblock(i, true)
}

fn inner_parse_unknownblock(i: &[u8], big_endian: bool) -> IResult<&[u8], Block, PcapError> {
    // debug!("Unknown block of ID {:x}", peek!(i, le_u32).unwrap().1);
    let read_u32 = if big_endian { be_u32 } else { le_u32 };
    do_parse! {
        i,
        blocktype: read_u32 >>
        len1:      verify!(read_u32, |val: &u32| *val >= 12) >>
        data:      take!(len1 - 12) >>
        len2:      verify!(read_u32, |x: &u32| *x == len1) >>
        (
            Block::Unknown(UnknownBlock {
                block_type: blocktype,
                block_len1: len1,
                data: data,
                block_len2: len2
            })
        )
    }
}

#[inline]
pub fn parse_unknownblock(i: &[u8]) -> IResult<&[u8], Block, PcapError> {
    inner_parse_unknownblock(i, false)
}

#[inline]
pub fn parse_unknownblock_be(i: &[u8]) -> IResult<&[u8], Block, PcapError> {
    inner_parse_unknownblock(i, true)
}

/// Parse any block, as little-endian
///
/// To find which endianess to use, read the section header
/// using `parse_sectionheaderblock`
pub fn parse_block(i: &[u8]) -> IResult<&[u8], Block, PcapError> {
    match peek!(i, call!(le_u32)) {
        Ok((rem, id)) => match id {
            SHB_MAGIC => parse_sectionheader(rem),
            IDB_MAGIC => parse_interfacedescriptionblock(rem),
            SPB_MAGIC => parse_simplepacketblock(rem),
            EPB_MAGIC => parse_enhancedpacketblock(rem),
            NRB_MAGIC => parse_nameresolutionblock(rem),
            ISB_MAGIC => parse_interfacestatisticsblock(rem),
            CB_MAGIC | DCB_MAGIC => parse_customblock(rem),
            _ => parse_unknownblock(rem),
        },
        Err(e) => Err(e),
    }
}

/// Parse any block, as big-endian
///
/// To find which endianess to use, read the section header
/// using `parse_sectionheaderblock`
pub fn parse_block_be(i: &[u8]) -> IResult<&[u8], Block, PcapError> {
    match peek!(i, call!(be_u32)) {
        Ok((rem, id)) => match id {
            SHB_MAGIC => parse_sectionheader(rem),
            IDB_MAGIC => parse_interfacedescriptionblock_be(rem),
            SPB_MAGIC => parse_simplepacketblock_be(rem),
            EPB_MAGIC => parse_enhancedpacketblock_be(rem),
            NRB_MAGIC => parse_nameresolutionblock_be(rem),
            ISB_MAGIC => parse_interfacestatisticsblock_be(rem),
            CB_MAGIC | DCB_MAGIC => parse_customblock_be(rem),
            _ => parse_unknownblock_be(rem),
        },
        Err(e) => Err(e),
    }
}

/// Parse any block from a section
pub fn parse_section_content_block(i: &[u8]) -> IResult<&[u8], Block, PcapError> {
    let (rem, block) = parse_block(i)?;
    match block {
        Block::SectionHeader(_) => Err(Err::Error(error_position!(i, ErrorKind::Tag))),
        _ => Ok((rem, block)),
    }
}

/// Parse any block from a section (big-endian version)
pub fn parse_section_content_block_be(i: &[u8]) -> IResult<&[u8], Block, PcapError> {
    let (rem, block) = parse_block_be(i)?;
    match block {
        Block::SectionHeader(_) => Err(Err::Error(error_position!(i, ErrorKind::Tag))),
        _ => Ok((rem, block)),
    }
}

/// Parse one section
pub fn parse_section(i: &[u8]) -> IResult<&[u8], Section, PcapError> {
    let (rem, shb) = parse_sectionheaderblock(i)?;
    let big_endian = shb.is_bigendian();
    let (rem, mut b) = if big_endian {
        many0!(rem, complete!(parse_section_content_block_be))?
    } else {
        many0!(rem, complete!(parse_section_content_block))?
    };
    let mut blocks = Vec::with_capacity(b.len() + 1);
    blocks.push(Block::SectionHeader(shb));
    blocks.append(&mut b);
    let section = Section { blocks, big_endian };
    Ok((rem, section))
}

/// Parse multiple sections
#[inline]
pub fn parse_sections(i: &[u8]) -> IResult<&[u8], Vec<Section>, PcapError> {
    many1!(i, complete!(parse_section))
}
