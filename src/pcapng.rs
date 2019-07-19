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

use crate::packet::{Linktype, PcapBlock};
use crate::traits::PcapNGBlock;
use crate::utils::Data;
use crate::{align32, align_n2};
use nom::{be_i64, be_u16, be_u32, le_i64, le_u16, le_u32, rest, Err, ErrorKind, IResult, Offset};
// use packet::{Packet,PacketHeader};
use byteorder::{ByteOrder, LittleEndian};
// use std::fmt;

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

    // /// Get a vector of packets, sorted by timestamp
    // /// The vector is allocated.
    // ///
    // /// Choose `sort_by` because it is likely the packets are already almost sorted,
    // /// or are series of almost-soted packets (if there are multiple interfaces)
    // pub fn sorted_by_timestamp(&self) -> Vec<Packet> {
    //     let mut v : Vec<_> = self.iter_packets().collect();
    //     v.sort_by(
    //         |a, b|
    //         a.header.ts_sec.cmp(&b.header.ts_sec).then(a.header.ts_fractional.cmp(&b.header.ts_fractional))
    //         );
    //     v
    // }
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

#[derive(Debug, PartialEq)]
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

#[derive(Debug, PartialEq)]
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
    raw_data: Data<'a>,
    big_endian: bool,
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

impl<'a> PcapNGBlock for EnhancedPacketBlock<'a> {
    #[inline]
    fn raw_data(&self) -> &[u8] {
        self.raw_data.as_slice()
    }
    #[inline]
    fn big_endian(&self) -> bool {
        self.big_endian
    }
    #[inline]
    fn data_len(&self) -> usize {
        self.origlen as usize
    }
    #[inline]
    fn data(&self) -> &[u8] {
        &self.raw_data[28..self.data_len()]
    }
    #[inline]
    fn header_len(&self) -> usize {
        28
    }
}

#[derive(Debug, PartialEq)]
pub struct SimplePacketBlock<'a> {
    pub block_type: u32,
    pub block_len1: u32,
    /// Original packet length
    pub origlen: u32,
    pub data: &'a [u8],
    pub block_len2: u32,
}

#[derive(Debug)]
pub struct NameRecord<'a> {
    pub record_type: u16,
    pub record_value: &'a [u8],
}

#[derive(Debug)]
pub struct NameResolutionBlock<'a> {
    big_endian: bool,
    pub block_type: u32,
    pub block_len1: u32,
    pub nr: Vec<NameRecord<'a>>,
    pub opt: &'a [u8],
    pub block_len2: u32,
}

#[derive(Debug, PartialEq)]
pub struct InterfaceStatisticsBlock<'a> {
    pub block_type: u32,
    pub block_len1: u32,
    pub if_id: u32,
    pub ts_high: u32,
    pub ts_low: u32,
    pub options: Vec<PcapNGOption<'a>>,
    pub block_len2: u32,
}

#[derive(Debug)]
pub struct CustomBlock<'a> {
    big_endian: bool,
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

#[derive(Debug, PartialEq)]
pub struct UnknownBlock<'a> {
    pub block_type: u32,
    pub block_len1: u32,
    pub data: &'a [u8],
    pub block_len2: u32,
}

#[derive(Debug, PartialEq)]
pub struct PcapNGOption<'a> {
    pub code: OptionCode,
    pub len: u16,
    pub value: &'a [u8],
}

#[derive(Debug, PartialEq)]
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

pub fn parse_option(i: &[u8]) -> IResult<&[u8], PcapNGOption> {
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

pub fn parse_option_be(i: &[u8]) -> IResult<&[u8], PcapNGOption> {
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

pub fn parse_sectionheaderblock_le(i: &[u8]) -> IResult<&[u8], SectionHeaderBlock> {
    do_parse! {
        i,
        magic:   verify!(le_u32, |x:u32| x == SHB_MAGIC) >>
              len1:    le_u32 >>
              bom:     verify!(le_u32, |x:u32| x == BOM_MAGIC) >>
              major:   le_u16 >>
              minor:   le_u16 >>
              slen:    le_i64 >>
              // options
              options: cond!(
                    len1 > 28,
                    flat_map!(
                        take!(len1 - 28),
                        many0!(complete!(parse_option))
                        )
                  ) >>
              len2:    verify!(le_u32, |x:u32| x == len1) >>
              (
                  SectionHeaderBlock{
                      block_type: magic,
                      block_len1: len1,
                      bom: bom,
                      major_version: major,
                      minor_version: minor,
                      section_len: slen,
                      options: options.unwrap_or(Vec::new()),
                      block_len2: len2
                  }
              )
    }
}

pub fn parse_sectionheaderblock_be(i: &[u8]) -> IResult<&[u8], SectionHeaderBlock> {
    do_parse! {
        i,
        magic:   verify!(be_u32, |x:u32| x == SHB_MAGIC) >>
              len1:    be_u32 >>
              bom:     le_u32 >>
              major:   be_u16 >>
              minor:   be_u16 >>
              slen:    be_i64 >>
              // options
              options: cond!(
                    len1 > 28,
                    flat_map!(
                        take!(len1 - 28),
                        many0!(complete!(parse_option_be))
                        )
                  ) >>
              len2:    verify!(be_u32, |x:u32| x == len1) >>
              (
                  SectionHeaderBlock{
                      block_type: magic,
                      block_len1: len1,
                      bom: bom,
                      major_version: major,
                      minor_version: minor,
                      section_len: slen,
                      options: options.unwrap_or(Vec::new()),
                      block_len2: len2
                  }
              )
    }
}

pub fn parse_sectionheaderblock(i: &[u8]) -> IResult<&[u8], SectionHeaderBlock> {
    peek!(i, tuple!(take!(8), le_u32)).and_then(|(rem, (_, bom))| {
        if bom == BOM_MAGIC {
            parse_sectionheaderblock_le(rem)
        } else if bom == u32::from_be(BOM_MAGIC) {
            parse_sectionheaderblock_be(rem)
        } else {
            Err(Err::Error(error_position!(i, ErrorKind::Tag)))
        }
    })
}

#[inline]
pub fn parse_sectionheader(i: &[u8]) -> IResult<&[u8], Block> {
    parse_sectionheaderblock_le(i).map(|(r, b)| (r, Block::SectionHeader(b)))
}

#[inline]
pub fn parse_sectionheader_be(i: &[u8]) -> IResult<&[u8], Block> {
    parse_sectionheaderblock_be(i).map(|(r, b)| (r, Block::SectionHeader(b)))
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
                    if_tsoffset = LittleEndian::read_u64(opt.value);
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
) -> IResult<&[u8], InterfaceDescriptionBlock> {
    let read_u16 = if big_endian { be_u16 } else { le_u16 };
    let read_u32 = if big_endian { be_u32 } else { le_u32 };
    let read_option = if big_endian {
        parse_option_be
    } else {
        parse_option
    };
    do_parse! {i,
              magic:      verify!(read_u32, |x:u32| x == IDB_MAGIC) >>
              len1:       read_u32 >>
              linktype:   read_u16 >>
              reserved:   read_u16 >>
              snaplen:    read_u32 >>
              // options
              options: cond!(
                    len1 > 20,
                    flat_map!(
                        take!(len1 - 20),
                        many0!(complete!(read_option))
                        )
                  ) >>
              len2:    verify!(read_u32, |x:u32| x == len1) >>
              ({
                  let options = options.unwrap_or(Vec::new());
                  let (if_tsresol, if_tsoffset) = if_extract_tsoffset_and_tsresol(&options);
                  InterfaceDescriptionBlock{
                      block_type: magic,
                      block_len1: len1,
                      linktype: Linktype(linktype as i32),
                      reserved,
                      snaplen,
                      options,
                      block_len2: len2,
                      if_tsresol,
                      if_tsoffset,
                  }
              })
    }
}

#[inline]
pub fn parse_interfacedescription(i: &[u8]) -> IResult<&[u8], InterfaceDescriptionBlock> {
    inner_parse_interfacedescription(i, false)
}

#[inline]
pub fn parse_interfacedescription_be(i: &[u8]) -> IResult<&[u8], InterfaceDescriptionBlock> {
    inner_parse_interfacedescription(i, true)
}
#[inline]
pub fn parse_interfacedescriptionblock(i: &[u8]) -> IResult<&[u8], Block> {
    parse_interfacedescription(i).map(|(r, b)| (r, Block::InterfaceDescription(b)))
}

#[inline]
pub fn parse_interfacedescriptionblock_be(i: &[u8]) -> IResult<&[u8], Block> {
    parse_interfacedescription_be(i).map(|(r, b)| (r, Block::InterfaceDescription(b)))
}

fn inner_parse_simplepacketblock(i: &[u8], big_endian: bool) -> IResult<&[u8], Block> {
    let read_u32 = if big_endian { be_u32 } else { le_u32 };
    do_parse! {
        i,
        magic:     verify!(read_u32, |x:u32| x == SPB_MAGIC) >>
        len1:      verify!(read_u32, |val:u32| val >= 32) >>
        origlen:   le_u32 >>
        // XXX if snaplen is < origlen, we MUST use snaplen
        // al_len:    value!(align32!(origlen)) >>
        // data:      take!(al_len) >>
        data:      take!(len1 - 16) >>
        len2:      verify!(read_u32, |x:u32| x == len1) >>
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
pub fn parse_simplepacketblock(i: &[u8]) -> IResult<&[u8], Block> {
    inner_parse_simplepacketblock(i, false)
}

/// Parse a Simple Packet Block (big-endian)
///
/// *Note: this function does not remove padding*
#[inline]
pub fn parse_simplepacketblock_be(i: &[u8]) -> IResult<&[u8], Block> {
    inner_parse_simplepacketblock(i, true)
}

#[inline]
fn current_position<'a>(j: &'a [u8], i: &'a [u8]) -> IResult<&'a [u8], usize> {
    debug_assert!(i.as_ptr() as u64 <= j.as_ptr() as u64);
    let offset = i.offset(j);
    Ok((j, offset))
}

fn inner_parse_enhancedpacketblock(i: &[u8], big_endian: bool) -> IResult<&[u8], Block> {
    let read_u32 = if big_endian { be_u32 } else { le_u32 };
    do_parse! {
        i,
                   verify!(read_u32, |x:u32| x == EPB_MAGIC) >>
        len1:      verify!(read_u32, |val:u32| val >= 32) >>
        if_id:     read_u32 >>
        ts_high:   read_u32 >>
        ts_low:    read_u32 >>
        caplen:    verify!(read_u32, |x| x < ::std::u32::MAX - 4) >>
        origlen:   read_u32 >>
        al_len:    value!(align32!(caplen)) >>
        data:      take!(al_len) >>
        options:   cond!(
              len1 > 32 + al_len,
              flat_map!(
                  take!(len1 - (32 + al_len)),
                  many0!(complete!(parse_option_be))
                  )
            ) >>
        len2:      verify!(read_u32, |x:u32| x == len1) >>
        pos:       call!(current_position, i) >>
        ({
            Block::EnhancedPacket(EnhancedPacketBlock{
                raw_data: Data::Borrowed(&i[..pos]),
                big_endian,
                block_type: EPB_MAGIC,
                block_len1: len1,
                if_id: if_id,
                ts_high: ts_high,
                ts_low: ts_low,
                caplen: caplen,
                origlen: origlen,
                data: data,
                options: options.unwrap_or(Vec::new()),
                block_len2: len2
            })
        })
    }
}

#[inline]
pub fn parse_enhancedpacketblock(i: &[u8]) -> IResult<&[u8], Block> {
    inner_parse_enhancedpacketblock(i, false)
}

#[inline]
pub fn parse_enhancedpacketblock_be(i: &[u8]) -> IResult<&[u8], Block> {
    inner_parse_enhancedpacketblock(i, true)
}

fn parse_name_record(i: &[u8], big_endian: bool) -> IResult<&[u8], NameRecord> {
    let read_u16 = if big_endian { be_u16 } else { le_u16 };
    do_parse! {
        i,
        record_type: read_u16 >>
        record_len: read_u16 >>
        record_value: take!(align32!(record_len)) >>
        (
            NameRecord{
                record_type,
                record_value,
            }
        )
    }
}

fn parse_name_record_list(i: &[u8], big_endian: bool) -> IResult<&[u8], Vec<NameRecord>> {
    many_till!(
        i,
        call!(parse_name_record, big_endian),
        verify!(le_u32, |x: u32| x == 0)
    )
    .map(|(rem, (v, _))| (rem, v))
}

fn inner_parse_nameresolutionblock(i: &[u8], big_endian: bool) -> IResult<&[u8], Block> {
    let read_u32 = if big_endian { be_u32 } else { le_u32 };
    do_parse! {
        i,
                    verify!(read_u32, |x:u32| x == NRB_MAGIC) >>
        len1:       verify!(read_u32, |val:u32| val >= 16) >>
        nr_and_opt: flat_map!(
            take!(len1 - 12),
            tuple!(call!(parse_name_record_list, big_endian), rest)
            ) >>
        len2:       verify!(read_u32, |x:u32| x == len1) >>
        ({
            Block::NameResolution(NameResolutionBlock{
                big_endian,
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
pub fn parse_nameresolutionblock(i: &[u8]) -> IResult<&[u8], Block> {
    inner_parse_nameresolutionblock(i, false)
}

#[inline]
pub fn parse_nameresolutionblock_be(i: &[u8]) -> IResult<&[u8], Block> {
    inner_parse_nameresolutionblock(i, true)
}

pub fn parse_interfacestatisticsblock(i: &[u8]) -> IResult<&[u8], Block> {
    do_parse! {
        i,
        magic:      verify!(le_u32, |x:u32| x == ISB_MAGIC) >>
        len1:       le_u32 >>
        if_id:      le_u32 >>
        ts_high:    le_u32 >>
        ts_low:     le_u32 >>
        // options
        options: cond!(
            len1 > 24,
            flat_map!(
                take!(len1 - 24),
                many0!(complete!(parse_option))
                )
            ) >>
        len2:    verify!(le_u32, |x:u32| x == len1) >>
        (
            Block::InterfaceStatistics(InterfaceStatisticsBlock{
                block_type: magic,
                block_len1: len1,
                if_id,
                ts_high,
                ts_low,
                options: options.unwrap_or(Vec::new()),
                block_len2: len2
            })
        )
    }
}

pub fn parse_interfacestatisticsblock_be(i: &[u8]) -> IResult<&[u8], Block> {
    do_parse! {
        i,
        magic:      verify!(be_u32, |x:u32| x == ISB_MAGIC) >>
        len1:       be_u32 >>
        if_id:      be_u32 >>
        ts_high:    be_u32 >>
        ts_low:     be_u32 >>
        // options
        options: cond!(
            len1 > 24,
            flat_map!(
                take!(len1 - 24),
                many0!(complete!(parse_option_be))
                )
            ) >>
        len2:    verify!(be_u32, |x:u32| x == len1) >>
        (
            Block::InterfaceStatistics(InterfaceStatisticsBlock{
                block_type: magic,
                block_len1: len1,
                if_id,
                ts_high,
                ts_low,
                options: options.unwrap_or(Vec::new()),
                block_len2: len2
            })
        )
    }
}

fn inner_parse_customblock(i: &[u8], big_endian: bool) -> IResult<&[u8], Block> {
    let read_u32 = if big_endian { be_u32 } else { le_u32 };
    do_parse! {
        i,
        blocktype: read_u32 >>
        len1:      verify!(read_u32, |val: u32| val >= 16) >>
        pen:       read_u32 >>
        data:      take!(len1 - 16) >>
        // options cannot be parsed, we don't know the length of data
        len2:      verify!(read_u32, |x: u32| x == len1) >>
        (
            Block::Custom(CustomBlock {
                big_endian,
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
pub fn parse_customblock(i: &[u8]) -> IResult<&[u8], Block> {
    inner_parse_customblock(i, false)
}

#[inline]
pub fn parse_customblock_be(i: &[u8]) -> IResult<&[u8], Block> {
    inner_parse_customblock(i, true)
}

fn inner_parse_unknownblock(i: &[u8], big_endian: bool) -> IResult<&[u8], Block> {
    // debug!("Unknown block of ID {:x}", peek!(i, le_u32).unwrap().1);
    let read_u32 = if big_endian { be_u32 } else { le_u32 };
    do_parse! {
        i,
        blocktype: read_u32 >>
        len1:      verify!(read_u32, |val: u32| val >= 12) >>
        data:      take!(len1 - 12) >>
        len2:      verify!(read_u32, |x: u32| x == len1) >>
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
pub fn parse_unknownblock(i: &[u8]) -> IResult<&[u8], Block> {
    inner_parse_unknownblock(i, false)
}

#[inline]
pub fn parse_unknownblock_be(i: &[u8]) -> IResult<&[u8], Block> {
    inner_parse_unknownblock(i, true)
}

/// Parse any block, as little-endian
///
/// To find which endianess to use, read the section header
/// using `parse_sectionheaderblock`
pub fn parse_block(i: &[u8]) -> IResult<&[u8], Block> {
    match peek!(i, le_u32) {
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
pub fn parse_block_be(i: &[u8]) -> IResult<&[u8], Block> {
    match peek!(i, be_u32) {
        Ok((rem, id)) => match id {
            SHB_MAGIC => parse_sectionheader_be(rem),
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
pub fn parse_section_content_block(i: &[u8]) -> IResult<&[u8], Block> {
    let (rem, block) = parse_block(i)?;
    match block {
        Block::SectionHeader(_) => Err(Err::Error(error_position!(i, ErrorKind::Tag))),
        _ => Ok((rem, block)),
    }
}

/// Parse any block from a section (big-endian version)
pub fn parse_section_content_block_be(i: &[u8]) -> IResult<&[u8], Block> {
    let (rem, block) = parse_block_be(i)?;
    match block {
        Block::SectionHeader(_) => Err(Err::Error(error_position!(i, ErrorKind::Tag))),
        _ => Ok((rem, block)),
    }
}

/// Parse one section
pub fn parse_section(i: &[u8]) -> IResult<&[u8], Section> {
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
pub fn parse_sections(i: &[u8]) -> IResult<&[u8], Vec<Section>> {
    many1!(i, complete!(parse_section))
}
