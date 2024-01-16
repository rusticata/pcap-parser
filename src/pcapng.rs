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
use crate::linktype::Linktype;
use crate::traits::*;
use crate::utils::*;
use nom::bytes::streaming::{tag, take};
use nom::combinator::{complete, map, map_parser};
use nom::error::*;
use nom::multi::{many0, many1, many_till};
use nom::number::streaming::{be_i64, be_u16, be_u32, le_i64, le_u16, le_u32};
use nom::{Err, IResult};
use rusticata_macros::{align32, newtype_enum};
use std::convert::TryFrom;

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

/// The Section Header Block (SHB) identifies the
/// beginning of a section of the capture capture file.
///
/// The
/// Section Header Block does not contain data but it rather identifies a
/// list of blocks (interfaces, packets) that are logically correlated.
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
    pub fn big_endian(&self) -> bool {
        self.bom != BOM_MAGIC
    }
}

impl<'a> PcapNGBlockParser<'a, PcapBE, SectionHeaderBlock<'a>> for SectionHeaderBlock<'a> {
    const HDR_SZ: usize = 28;
    const MAGIC: u32 = SHB_MAGIC;

    fn inner_parse<E: ParseError<&'a [u8]>>(
        block_type: u32,
        block_len1: u32,
        i: &'a [u8],
        block_len2: u32,
    ) -> IResult<&'a [u8], SectionHeaderBlock<'a>, E> {
        // caller function already tested header type(magic) and length
        // read end of header
        let (i, bom) = le_u32(i)?;
        let (i, major_version) = be_u16(i)?;
        let (i, minor_version) = be_u16(i)?;
        let (i, section_len) = be_i64(i)?;
        let (i, options) = opt_parse_options::<PcapBE, E>(i, block_len1 as usize, 28)?;
        let block = SectionHeaderBlock {
            block_type,
            block_len1,
            bom,
            major_version,
            minor_version,
            section_len,
            options,
            block_len2,
        };
        Ok((i, block))
    }
}

impl<'a> PcapNGBlockParser<'a, PcapLE, SectionHeaderBlock<'a>> for SectionHeaderBlock<'a> {
    const HDR_SZ: usize = 28;
    const MAGIC: u32 = SHB_MAGIC;

    fn inner_parse<E: ParseError<&'a [u8]>>(
        block_type: u32,
        block_len1: u32,
        i: &'a [u8],
        block_len2: u32,
    ) -> IResult<&'a [u8], SectionHeaderBlock<'a>, E> {
        // caller function already tested header type(magic) and length
        // read end of header
        let (i, bom) = le_u32(i)?;
        let (i, major_version) = le_u16(i)?;
        let (i, minor_version) = le_u16(i)?;
        let (i, section_len) = le_i64(i)?;
        let (i, options) = opt_parse_options::<PcapLE, E>(i, block_len1 as usize, 28)?;
        let block = SectionHeaderBlock {
            block_type,
            block_len1,
            bom,
            major_version,
            minor_version,
            section_len,
            options,
            block_len2,
        };
        Ok((i, block))
    }
}

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
    pub if_tsoffset: u64,
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
    pub fn ts_offset(&self) -> u64 {
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

/// An Enhanced Packet Block (EPB) is the standard container for storing
/// the packets coming from the network.
///
/// This struct is a thin abstraction layer, and stores the raw block data.
/// For ex the `data` field is stored with the padding.
/// It implements the `PcapNGPacketBlock` trait, which provides helper functions.
///
/// ## Examples
///
/// ```rust
/// use pcap_parser::pcapng::parse_enhancedpacketblock_le;
/// use pcap_parser::traits::PcapNGPacketBlock;
///
/// # let input_data = include_bytes!("../assets/test001-le.pcapng");
/// # let pcap_data = &input_data[148..=495];
/// let (i, epb) = parse_enhancedpacketblock_le(pcap_data).unwrap();
/// let packet_data = epb.packet_data();
/// if packet_data.len() < epb.orig_len() as usize {
///     // packet was truncated
/// } else {
///     // we have a full packet
/// }
/// ```
#[derive(Debug)]
pub struct EnhancedPacketBlock<'a> {
    // Block type, read as little-endian.
    // If block value is the reverse the the expected magic, this means block is encoded as big-endian
    pub block_type: u32,
    pub block_len1: u32,
    pub if_id: u32,
    pub ts_high: u32,
    pub ts_low: u32,
    /// Captured packet length
    pub caplen: u32,
    /// Original packet length
    pub origlen: u32,
    /// Raw data from packet (with padding)
    pub data: &'a [u8],
    pub options: Vec<PcapNGOption<'a>>,
    pub block_len2: u32,
}

impl<'a> EnhancedPacketBlock<'a> {
    /// Decode the packet timestamp
    ///
    /// To decode the timestamp, the raw values if_tsresol and if_tsoffset are required.
    /// These values are stored as options in the [`InterfaceDescriptionBlock`]
    /// matching the interface ID.
    ///
    /// Return the timestamp seconds and fractional part (in resolution units)
    #[inline]
    pub fn decode_ts(&self, ts_offset: u64, resolution: u64) -> (u32, u32) {
        build_ts(self.ts_high, self.ts_low, ts_offset, resolution)
    }

    /// Decode the packet timestamp as `f64`
    ///
    /// To decode the timestamp, the resolution and offset are required.
    /// These values are stored as options in the [`InterfaceDescriptionBlock`]
    /// matching the interface ID.
    #[inline]
    pub fn decode_ts_f64(&self, ts_offset: u64, resolution: u64) -> f64 {
        build_ts_f64(self.ts_high, self.ts_low, ts_offset, resolution)
    }
}

impl<'a> PcapNGPacketBlock for EnhancedPacketBlock<'a> {
    fn big_endian(&self) -> bool {
        self.block_type != EPB_MAGIC
    }
    fn truncated(&self) -> bool {
        self.origlen != self.caplen
    }
    fn orig_len(&self) -> u32 {
        self.origlen
    }
    fn raw_packet_data(&self) -> &[u8] {
        self.data
    }
    fn packet_data(&self) -> &[u8] {
        let caplen = self.caplen as usize;
        if caplen < self.data.len() {
            &self.data[..caplen]
        } else {
            self.data
        }
    }
}

impl<'a, En: PcapEndianness> PcapNGBlockParser<'a, En, EnhancedPacketBlock<'a>>
    for EnhancedPacketBlock<'a>
{
    const HDR_SZ: usize = 32;
    const MAGIC: u32 = EPB_MAGIC;

    fn inner_parse<E: ParseError<&'a [u8]>>(
        block_type: u32,
        block_len1: u32,
        i: &'a [u8],
        block_len2: u32,
    ) -> IResult<&'a [u8], EnhancedPacketBlock<'a>, E> {
        // caller function already tested header type(magic) and length
        // read end of header
        let (b_hdr, packet_data) = i.split_at(20);
        let if_id = En::u32_from_bytes(*array_ref4(b_hdr, 0));
        let ts_high = En::u32_from_bytes(*array_ref4(b_hdr, 4));
        let ts_low = En::u32_from_bytes(*array_ref4(b_hdr, 8));
        let caplen = En::u32_from_bytes(*array_ref4(b_hdr, 12));
        let origlen = En::u32_from_bytes(*array_ref4(b_hdr, 16));
        // read packet data
        // align32 can overflow
        if caplen >= ::std::u32::MAX - 4 {
            return Err(Err::Error(E::from_error_kind(i, ErrorKind::Verify)));
        }
        let padded_length = align32!(caplen);
        let (i, data) = take(padded_length)(packet_data)?;
        // read options
        let current_offset = (32 + padded_length) as usize;
        let (i, options) = opt_parse_options::<En, E>(i, block_len1 as usize, current_offset)?;
        if block_len2 != block_len1 {
            return Err(Err::Error(E::from_error_kind(i, ErrorKind::Verify)));
        }
        let block = EnhancedPacketBlock {
            block_type,
            block_len1,
            if_id,
            ts_high,
            ts_low,
            caplen,
            origlen,
            data,
            options,
            block_len2,
        };
        Ok((i, block))
    }
}

/// The Simple Packet Block (SPB) is a lightweight container for storing
/// the packets coming from the network.
///
/// This struct is a thin abstraction layer, and stores the raw block data.
/// For ex the `data` field is stored with the padding.
/// It implements the `PcapNGPacketBlock` trait, which provides helper functions.
#[derive(Debug)]
pub struct SimplePacketBlock<'a> {
    /// Block type (little endian)
    pub block_type: u32,
    pub block_len1: u32,
    /// Original packet length
    pub origlen: u32,
    pub data: &'a [u8],
    pub block_len2: u32,
}

impl<'a> PcapNGPacketBlock for SimplePacketBlock<'a> {
    fn big_endian(&self) -> bool {
        self.block_type != SPB_MAGIC
    }
    fn truncated(&self) -> bool {
        self.origlen as usize <= self.data.len()
    }
    fn orig_len(&self) -> u32 {
        self.origlen
    }
    fn raw_packet_data(&self) -> &[u8] {
        self.data
    }
    fn packet_data(&self) -> &[u8] {
        let caplen = self.origlen as usize;
        if caplen < self.data.len() {
            &self.data[..caplen]
        } else {
            self.data
        }
    }
}

impl<'a, En: PcapEndianness> PcapNGBlockParser<'a, En, SimplePacketBlock<'a>>
    for SimplePacketBlock<'a>
{
    const HDR_SZ: usize = 16;
    const MAGIC: u32 = SPB_MAGIC;

    fn inner_parse<E: ParseError<&'a [u8]>>(
        block_type: u32,
        block_len1: u32,
        i: &'a [u8],
        block_len2: u32,
    ) -> IResult<&'a [u8], SimplePacketBlock<'a>, E> {
        // caller function already tested header type(magic) and length
        // read end of header
        let (i, origlen) = En::parse_u32(i)?;
        let (i, data) = take((block_len1 as usize) - 16)(i)?;
        let block = SimplePacketBlock {
            block_type,
            block_len1,
            origlen,
            data,
            block_len2,
        };
        Ok((i, block))
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct NameRecordType(pub u16);

newtype_enum! {
    impl debug NameRecordType {
        End = 0,
        Ipv4 = 1,
        Ipv6 = 2
    }
}

#[derive(Debug)]
pub struct NameRecord<'a> {
    pub record_type: NameRecordType,
    pub record_value: &'a [u8],
}

impl<'a> NameRecord<'a> {
    pub const END: NameRecord<'static> = NameRecord {
        record_type: NameRecordType::End,
        record_value: &[],
    };
}

#[derive(Debug)]
pub struct NameResolutionBlock<'a> {
    pub block_type: u32,
    pub block_len1: u32,
    pub nr: Vec<NameRecord<'a>>,
    pub options: Vec<PcapNGOption<'a>>,
    pub block_len2: u32,
}

impl<'a, En: PcapEndianness> PcapNGBlockParser<'a, En, NameResolutionBlock<'a>>
    for NameResolutionBlock<'a>
{
    const HDR_SZ: usize = 12;
    const MAGIC: u32 = NRB_MAGIC;

    fn inner_parse<E: ParseError<&'a [u8]>>(
        block_type: u32,
        block_len1: u32,
        i: &'a [u8],
        block_len2: u32,
    ) -> IResult<&'a [u8], NameResolutionBlock<'a>, E> {
        let start_i = i;
        // caller function already tested header type(magic) and length
        // read records
        let (i, nr) = parse_name_record_list::<En, E>(i)?;
        // read options
        let current_offset = 12 + (i.as_ptr() as usize) - (start_i.as_ptr() as usize);
        let (i, options) = opt_parse_options::<En, E>(i, block_len1 as usize, current_offset)?;
        if block_len2 != block_len1 {
            return Err(Err::Error(E::from_error_kind(i, ErrorKind::Verify)));
        }
        let block = NameResolutionBlock {
            block_type,
            block_len1,
            nr,
            options,
            block_len2,
        };
        Ok((i, block))
    }
}

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

#[derive(Debug)]
pub struct SystemdJournalExportBlock<'a> {
    pub block_type: u32,
    pub block_len1: u32,
    pub data: &'a [u8],
    pub block_len2: u32,
}

impl<'a, En: PcapEndianness> PcapNGBlockParser<'a, En, SystemdJournalExportBlock<'a>>
    for SystemdJournalExportBlock<'a>
{
    const HDR_SZ: usize = 12;
    const MAGIC: u32 = SJE_MAGIC;

    fn inner_parse<E: ParseError<&'a [u8]>>(
        block_type: u32,
        block_len1: u32,
        i: &'a [u8],
        block_len2: u32,
    ) -> IResult<&'a [u8], SystemdJournalExportBlock<'a>, E> {
        let block = SystemdJournalExportBlock {
            block_type,
            block_len1,
            data: i,
            block_len2,
        };
        Ok((i, block))
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct SecretsType(pub u32);

newtype_enum! {
    impl debug SecretsType {
        TlsKeyLog = 0x544c_534b, // TLSK
        WireguardKeyLog = 0x5747_4b4c,
    }
}

#[derive(Debug)]
pub struct DecryptionSecretsBlock<'a> {
    pub block_type: u32,
    pub block_len1: u32,
    pub secrets_type: SecretsType,
    pub secrets_len: u32,
    pub data: &'a [u8],
    pub options: Vec<PcapNGOption<'a>>,
    pub block_len2: u32,
}

impl<'a, En: PcapEndianness> PcapNGBlockParser<'a, En, DecryptionSecretsBlock<'a>>
    for DecryptionSecretsBlock<'a>
{
    const HDR_SZ: usize = 20;
    const MAGIC: u32 = DSB_MAGIC;

    fn inner_parse<E: ParseError<&'a [u8]>>(
        block_type: u32,
        block_len1: u32,
        i: &'a [u8],
        block_len2: u32,
    ) -> IResult<&'a [u8], DecryptionSecretsBlock<'a>, E> {
        // caller function already tested header type(magic) and length
        // read end of header
        let (i, secrets_type) = En::parse_u32(i)?;
        let (i, secrets_len) = En::parse_u32(i)?;
        // read packet data
        // align32 can overflow
        if secrets_len >= ::std::u32::MAX - 4 {
            return Err(Err::Error(E::from_error_kind(i, ErrorKind::Verify)));
        }
        let padded_length = align32!(secrets_len);
        let (i, data) = take(padded_length)(i)?;
        // read options
        let current_offset = (20 + padded_length) as usize;
        let (i, options) = opt_parse_options::<En, E>(i, block_len1 as usize, current_offset)?;
        if block_len2 != block_len1 {
            return Err(Err::Error(E::from_error_kind(i, ErrorKind::Verify)));
        }
        let block = DecryptionSecretsBlock {
            block_type,
            block_len1,
            secrets_type: SecretsType(secrets_type),
            secrets_len,
            data,
            options,
            block_len2,
        };
        Ok((i, block))
    }
}

#[derive(Debug)]
pub struct CustomBlock<'a> {
    pub block_type: u32,
    pub block_len1: u32,
    // Private Enterprise Number (PEN)
    pub pen: u32,
    pub data: &'a [u8],
    // pub options: &'a [u8],
    pub block_len2: u32,
}

impl<'a, En: PcapEndianness> PcapNGBlockParser<'a, En, CustomBlock<'a>> for CustomBlock<'a> {
    const HDR_SZ: usize = 16;
    const MAGIC: u32 = CB_MAGIC;

    fn inner_parse<E: ParseError<&'a [u8]>>(
        block_type: u32,
        block_len1: u32,
        i: &'a [u8],
        block_len2: u32,
    ) -> IResult<&'a [u8], CustomBlock<'a>, E> {
        // caller function already tested header type(magic) and length
        // read end of header
        let (i, pen) = En::parse_u32(i)?;
        // there is no way to differentiate custom data and options,
        // since length of data is not provided
        let data = i;
        if block_len2 != block_len1 {
            return Err(Err::Error(E::from_error_kind(i, ErrorKind::Verify)));
        }
        let block = CustomBlock {
            block_type,
            block_len1,
            pen,
            data,
            block_len2,
        };
        Ok((i, block))
    }
}

struct DCBParser;
impl<'a, En: PcapEndianness> PcapNGBlockParser<'a, En, CustomBlock<'a>> for DCBParser {
    const HDR_SZ: usize = 16;
    const MAGIC: u32 = DCB_MAGIC;

    fn inner_parse<E: ParseError<&'a [u8]>>(
        block_type: u32,
        block_len1: u32,
        i: &'a [u8],
        block_len2: u32,
    ) -> IResult<&'a [u8], CustomBlock<'a>, E> {
        <CustomBlock as PcapNGBlockParser<En, CustomBlock<'a>>>::inner_parse::<E>(
            block_type, block_len1, i, block_len2,
        )
    }
}

impl<'a> CustomBlock<'a> {
    pub fn do_not_copy(&self) -> bool {
        self.block_type == DCB_MAGIC || self.block_type == DCB_MAGIC.swap_bytes()
    }
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
            return Err(nom::Err::Incomplete(nom::Needed::new(P::HDR_SZ - i.len())));
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
        value,
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

pub fn parse_sectionheaderblock_le(
    i: &[u8],
) -> IResult<&[u8], SectionHeaderBlock, PcapError<&[u8]>> {
    ng_block_parser::<SectionHeaderBlock, PcapLE, _, _>()(i)
}

pub fn parse_sectionheaderblock_be(
    i: &[u8],
) -> IResult<&[u8], SectionHeaderBlock, PcapError<&[u8]>> {
    ng_block_parser::<SectionHeaderBlock, PcapBE, _, _>()(i)
}

/// Parse a SectionHeaderBlock (little or big endian)
pub fn parse_sectionheaderblock(i: &[u8]) -> IResult<&[u8], SectionHeaderBlock, PcapError<&[u8]>> {
    if i.len() < 12 {
        return Err(nom::Err::Incomplete(nom::Needed::new(12 - i.len())));
    }
    let bom = u32::from_le_bytes(*array_ref4(i, 8));
    if bom == BOM_MAGIC {
        parse_sectionheaderblock_le(i)
    } else if bom == u32::from_be(BOM_MAGIC) {
        parse_sectionheaderblock_be(i)
    } else {
        Err(Err::Error(PcapError::HeaderNotRecognized))
    }
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
                    let int_bytes =
                        <[u8; 8]>::try_from(&opt.value[..8]).expect("Convert bytes to u64");
                    if_tsoffset = u64::from_le_bytes(int_bytes);
                }
            }
            _ => (),
        }
    }
    (if_tsresol, if_tsoffset)
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

/// Parse a Simple Packet Block (little-endian)
///
/// *Note: this function does not remove padding in the `data` field.
/// Use `packet_data` to get field without padding.*
pub fn parse_simplepacketblock_le(i: &[u8]) -> IResult<&[u8], SimplePacketBlock, PcapError<&[u8]>> {
    ng_block_parser::<SimplePacketBlock, PcapLE, _, _>()(i)
}

/// Parse a Simple Packet Block (big-endian)
///
/// *Note: this function does not remove padding*
pub fn parse_simplepacketblock_be(i: &[u8]) -> IResult<&[u8], SimplePacketBlock, PcapError<&[u8]>> {
    ng_block_parser::<SimplePacketBlock, PcapBE, _, _>()(i)
}

/// Parse an Enhanced Packet Block (little-endian)
pub fn parse_enhancedpacketblock_le(
    i: &[u8],
) -> IResult<&[u8], EnhancedPacketBlock, PcapError<&[u8]>> {
    ng_block_parser::<EnhancedPacketBlock, PcapLE, _, _>()(i)
}

/// Parse an Enhanced Packet Block (big-endian)
pub fn parse_enhancedpacketblock_be(
    i: &[u8],
) -> IResult<&[u8], EnhancedPacketBlock, PcapError<&[u8]>> {
    ng_block_parser::<EnhancedPacketBlock, PcapBE, _, _>()(i)
}

fn parse_name_record<'a, En: PcapEndianness, E: ParseError<&'a [u8]>>(
    i: &'a [u8],
) -> IResult<&'a [u8], NameRecord, E> {
    let (i, record_type) = En::parse_u16(i)?;
    let (i, record_len) = En::parse_u16(i)?;
    let aligned_len = align32!(record_len as u32);
    let (i, record_value) = take(aligned_len)(i)?;
    let name_record = NameRecord {
        record_type: NameRecordType(record_type),
        record_value,
    };
    Ok((i, name_record))
}

fn parse_name_record_list<'a, En: PcapEndianness, E: ParseError<&'a [u8]>>(
    i: &'a [u8],
) -> IResult<&'a [u8], Vec<NameRecord>, E> {
    map(
        many_till(parse_name_record::<En, E>, tag(b"\x00\x00\x00\x00")),
        |(mut v, _)| {
            v.push(NameRecord::END);
            v
        },
    )(i)
}

#[inline]
pub fn parse_nameresolutionblock_le(
    i: &[u8],
) -> IResult<&[u8], NameResolutionBlock, PcapError<&[u8]>> {
    ng_block_parser::<NameResolutionBlock, PcapLE, _, _>()(i)
}

#[inline]
pub fn parse_nameresolutionblock_be(
    i: &[u8],
) -> IResult<&[u8], NameResolutionBlock, PcapError<&[u8]>> {
    ng_block_parser::<NameResolutionBlock, PcapBE, _, _>()(i)
}

pub fn parse_interfacestatisticsblock_le(
    i: &[u8],
) -> IResult<&[u8], InterfaceStatisticsBlock, PcapError<&[u8]>> {
    ng_block_parser::<InterfaceStatisticsBlock, PcapLE, _, _>()(i)
}

pub fn parse_interfacestatisticsblock_be(
    i: &[u8],
) -> IResult<&[u8], InterfaceStatisticsBlock, PcapError<&[u8]>> {
    ng_block_parser::<InterfaceStatisticsBlock, PcapBE, _, _>()(i)
}

#[inline]
pub fn parse_systemdjournalexportblock_le(
    i: &[u8],
) -> IResult<&[u8], SystemdJournalExportBlock, PcapError<&[u8]>> {
    ng_block_parser::<SystemdJournalExportBlock, PcapLE, _, _>()(i)
}

#[inline]
pub fn parse_systemdjournalexportblock_be(
    i: &[u8],
) -> IResult<&[u8], SystemdJournalExportBlock, PcapError<&[u8]>> {
    ng_block_parser::<SystemdJournalExportBlock, PcapBE, _, _>()(i)
}

#[inline]
pub fn parse_decryptionsecretsblock_le(
    i: &[u8],
) -> IResult<&[u8], DecryptionSecretsBlock, PcapError<&[u8]>> {
    ng_block_parser::<DecryptionSecretsBlock, PcapLE, _, _>()(i)
}

#[inline]
pub fn parse_decryptionsecretsblock_be(
    i: &[u8],
) -> IResult<&[u8], DecryptionSecretsBlock, PcapError<&[u8]>> {
    ng_block_parser::<DecryptionSecretsBlock, PcapBE, _, _>()(i)
}

#[inline]
pub fn parse_customblock_le(i: &[u8]) -> IResult<&[u8], CustomBlock, PcapError<&[u8]>> {
    ng_block_parser::<CustomBlock, PcapLE, _, _>()(i)
}

#[inline]
pub fn parse_customblock_be(i: &[u8]) -> IResult<&[u8], CustomBlock, PcapError<&[u8]>> {
    ng_block_parser::<CustomBlock, PcapBE, _, _>()(i)
}

#[inline]
pub fn parse_dcb_le(i: &[u8]) -> IResult<&[u8], CustomBlock, PcapError<&[u8]>> {
    ng_block_parser::<DCBParser, PcapLE, _, _>()(i)
}

#[inline]
pub fn parse_dcb_be(i: &[u8]) -> IResult<&[u8], CustomBlock, PcapError<&[u8]>> {
    ng_block_parser::<DCBParser, PcapBE, _, _>()(i)
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
