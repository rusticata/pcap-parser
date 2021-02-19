//! PCAPNG file format
//!
//! See <https://github.com/pcapng/pcapng> for details.
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
use crate::endianness::*;
use crate::error::PcapError;
use crate::linktype::Linktype;
use crate::traits::*;
use crate::utils::*;
use nom::bytes::complete::take;
use nom::combinator::{complete, map, map_parser, rest};
use nom::error::*;
use nom::multi::{many0, many1};
use nom::number::streaming::{be_i64, be_u16, be_u32, le_i64, le_u16, le_u32};
use nom::{
    call, do_parse, error_position, flat_map, many_till, peek, take, tuple, verify, Err, IResult,
};
use rusticata_macros::{align32, newtype_enum, q};
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
        let (i, options) = opt_parse_options_be(i, block_len1 as usize, 28)?;
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
        let (i, options) = opt_parse_options(i, block_len1 as usize, 28)?;
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
        let (i, options) = En::opt_parse_options(i, block_len1 as usize, 20)?;
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
    /// To decode the timestamp, the resolution and offset are required.
    /// These values are stored as options in the `InterfaceDescriptionBlock`
    /// matching the interface ID.
    #[inline]
    pub fn decode_ts(&self, ts_offset: u64, ts_resol: u8) -> (u32, u32, u64) {
        build_ts(self.ts_high, self.ts_low, ts_offset, ts_resol)
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
        let padded_length = align32!(caplen);
        let (i, data) = take(padded_length)(packet_data)?;
        // read options
        let current_offset = (32 + padded_length) as usize;
        let (i, options) = En::opt_parse_options(i, block_len1 as usize, current_offset)?;
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

#[derive(Debug)]
pub struct NameResolutionBlock<'a> {
    pub block_type: u32,
    pub block_len1: u32,
    pub nr: Vec<NameRecord<'a>>,
    pub opt: &'a [u8],
    pub block_len2: u32,
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

#[derive(Debug)]
pub struct SystemdJournalExportBlock<'a> {
    pub block_type: u32,
    pub block_len1: u32,
    pub data: &'a [u8],
    pub block_len2: u32,
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

impl<'a> CustomBlock<'a> {
    pub fn do_not_copy(&self) -> bool {
        self.block_type == DCB_MAGIC
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
            return Err(nom::Err::Incomplete(nom::Needed::new(P::HDR_SZ)));
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

pub(crate) fn opt_parse_options<'i, E: ParseError<&'i [u8]>>(
    i: &'i [u8],
    len: usize,
    opt_offset: usize,
) -> IResult<&'i [u8], Vec<PcapNGOption>, E> {
    if len > opt_offset {
        map_parser(take(len - opt_offset), many0(complete(parse_option)))(i)
    } else {
        Ok((i, Vec::new()))
    }
}

pub(crate) fn opt_parse_options_be<'i, E: ParseError<&'i [u8]>>(
    i: &'i [u8],
    len: usize,
    opt_offset: usize,
) -> IResult<&'i [u8], Vec<PcapNGOption>, E> {
    if len > opt_offset {
        map_parser(take(len - opt_offset), many0(complete(parse_option_be)))(i)
    } else {
        Ok((i, Vec::new()))
    }
}

pub fn parse_sectionheaderblock_le(i: &[u8]) -> IResult<&[u8], SectionHeaderBlock, PcapError> {
    ng_block_parser::<SectionHeaderBlock, PcapLE, _, _>()(i)
}

pub fn parse_sectionheaderblock_be(i: &[u8]) -> IResult<&[u8], SectionHeaderBlock, PcapError> {
    ng_block_parser::<SectionHeaderBlock, PcapBE, _, _>()(i)
}

/// Parse a SectionHeaderBlock (little or big endian)
pub fn parse_sectionheaderblock(i: &[u8]) -> IResult<&[u8], SectionHeaderBlock, PcapError> {
    if i.len() < 12 {
        return Err(nom::Err::Incomplete(nom::Needed::new(12)));
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

/// Parse a SectionHeaderBlock (little or big endian)
#[deprecated(
    since = "0.11.0",
    note = "Please use the parse_sectionheaderblock function instead"
)]
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
) -> IResult<&[u8], InterfaceDescriptionBlock, PcapError> {
    ng_block_parser::<InterfaceDescriptionBlock, PcapLE, _, _>()(i)
}

/// Parse an Interface Packet Block (big-endian)
pub fn parse_interfacedescriptionblock_be(
    i: &[u8],
) -> IResult<&[u8], InterfaceDescriptionBlock, PcapError> {
    ng_block_parser::<InterfaceDescriptionBlock, PcapBE, _, _>()(i)
}

/// Parse a Simple Packet Block (little-endian)
///
/// *Note: this function does not remove padding in the `data` field.
/// Use `packet_data` to get field without padding.*
pub fn parse_simplepacketblock_le(i: &[u8]) -> IResult<&[u8], SimplePacketBlock, PcapError> {
    ng_block_parser::<SimplePacketBlock, PcapLE, _, _>()(i)
}

/// Parse a Simple Packet Block (big-endian)
///
/// *Note: this function does not remove padding*
pub fn parse_simplepacketblock_be(i: &[u8]) -> IResult<&[u8], SimplePacketBlock, PcapError> {
    ng_block_parser::<SimplePacketBlock, PcapBE, _, _>()(i)
}

/// Parse an Enhanced Packet Block (little-endian)
pub fn parse_enhancedpacketblock_le(i: &[u8]) -> IResult<&[u8], EnhancedPacketBlock, PcapError> {
    ng_block_parser::<EnhancedPacketBlock, PcapLE, _, _>()(i)
}

/// Parse an Enhanced Packet Block (big-endian)
pub fn parse_enhancedpacketblock_be(i: &[u8]) -> IResult<&[u8], EnhancedPacketBlock, PcapError> {
    ng_block_parser::<EnhancedPacketBlock, PcapBE, _, _>()(i)
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
                record_type: NameRecordType(record_type),
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

fn inner_parse_systemdjournalexportblock(
    i: &[u8],
    big_endian: bool,
) -> IResult<&[u8], Block, PcapError> {
    let read_u32 = if big_endian { be_u32 } else { le_u32 };
    do_parse! {
        i,
        block_type:   verify!(read_u32, |x:&u32| *x == SJE_MAGIC) >>
        block_len1:   verify!(read_u32, |val: &u32| *val >= 12) >>
        data:         take!(block_len1 - 12) >>
        // no options in this block
        block_len2:   verify!(read_u32, |x: &u32| *x == block_len1) >>
        (
            Block::SystemdJournalExport(SystemdJournalExportBlock {
                block_type,
                block_len1,
                data,
                block_len2,
            })
        )
    }
}

#[inline]
pub fn parse_systemdjournalexportblock(i: &[u8]) -> IResult<&[u8], Block, PcapError> {
    inner_parse_systemdjournalexportblock(i, false)
}

#[inline]
pub fn parse_systemdjournalexportblock_be(i: &[u8]) -> IResult<&[u8], Block, PcapError> {
    inner_parse_systemdjournalexportblock(i, true)
}

fn inner_parse_decryptionsecretsblock(
    i: &[u8],
    big_endian: bool,
) -> IResult<&[u8], Block, PcapError> {
    let read_u32 = if big_endian { be_u32 } else { le_u32 };
    let read_options = if big_endian {
        opt_parse_options_be
    } else {
        opt_parse_options
    };
    do_parse! {
        i,
        block_type:   verify!(read_u32, |x:&u32| *x == DSB_MAGIC) >>
        block_len1:   verify!(read_u32, |val: &u32| *val >= 16) >>
        secrets_type: read_u32 >>
        secrets_len:  verify!(read_u32, |x| *x < ::std::u32::MAX - 4) >>
        al_len:       q!(align32!(secrets_len) as usize) >>
        data:         take!(al_len) >>
        options:      call!(read_options, block_len1 as usize, 24 + al_len) >>
        block_len2:   verify!(read_u32, |x: &u32| *x == block_len1) >>
        (
            Block::DecryptionSecrets(DecryptionSecretsBlock {
                block_type,
                block_len1,
                secrets_type: SecretsType(secrets_type),
                secrets_len,
                data,
                options,
                block_len2,
            })
        )
    }
}

#[inline]
pub fn parse_decryptionsecretsblock(i: &[u8]) -> IResult<&[u8], Block, PcapError> {
    inner_parse_decryptionsecretsblock(i, false)
}

#[inline]
pub fn parse_decryptionsecretsblock_be(i: &[u8]) -> IResult<&[u8], Block, PcapError> {
    inner_parse_decryptionsecretsblock(i, true)
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

/// Parse an unknown block (little-endian)
pub fn parse_unknownblock_le(i: &[u8]) -> IResult<&[u8], UnknownBlock, PcapError> {
    ng_block_parser::<UnknownBlock, PcapLE, _, _>()(i)
}

/// Parse an unknown block (big-endian)
pub fn parse_unknownblock_be(i: &[u8]) -> IResult<&[u8], UnknownBlock, PcapError> {
    ng_block_parser::<UnknownBlock, PcapBE, _, _>()(i)
}

#[deprecated(
    since = "0.11.0",
    note = "Please use the parse_block_le function instead"
)]
#[inline]
pub fn parse_block(i: &[u8]) -> IResult<&[u8], Block, PcapError> {
    parse_block_le(i)
}

/// Parse any block, as little-endian
///
/// To find which endianess to use, read the section header
/// using `parse_sectionheaderblock`
pub fn parse_block_le(i: &[u8]) -> IResult<&[u8], Block, PcapError> {
    match peek!(i, call!(le_u32)) {
        Ok((rem, id)) => match id {
            SHB_MAGIC => map(parse_sectionheaderblock, Block::SectionHeader)(rem),
            IDB_MAGIC => map(
                parse_interfacedescriptionblock_le,
                Block::InterfaceDescription,
            )(rem),
            SPB_MAGIC => map(parse_simplepacketblock_le, Block::SimplePacket)(rem),
            EPB_MAGIC => map(parse_enhancedpacketblock_le, Block::EnhancedPacket)(rem),
            NRB_MAGIC => parse_nameresolutionblock(rem),
            ISB_MAGIC => parse_interfacestatisticsblock(rem),
            SJE_MAGIC => parse_systemdjournalexportblock(rem),
            DSB_MAGIC => parse_decryptionsecretsblock(rem),
            CB_MAGIC | DCB_MAGIC => parse_customblock(rem),
            _ => map(parse_unknownblock_le, Block::Unknown)(rem),
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
            SHB_MAGIC => map(parse_sectionheaderblock, Block::SectionHeader)(rem),
            IDB_MAGIC => map(
                parse_interfacedescriptionblock_be,
                Block::InterfaceDescription,
            )(rem),
            SPB_MAGIC => map(parse_simplepacketblock_be, Block::SimplePacket)(rem),
            EPB_MAGIC => map(parse_enhancedpacketblock_be, Block::EnhancedPacket)(rem),
            NRB_MAGIC => parse_nameresolutionblock_be(rem),
            ISB_MAGIC => parse_interfacestatisticsblock_be(rem),
            SJE_MAGIC => parse_systemdjournalexportblock_be(rem),
            DSB_MAGIC => parse_decryptionsecretsblock_be(rem),
            CB_MAGIC | DCB_MAGIC => parse_customblock_be(rem),
            _ => map(parse_unknownblock_be, Block::Unknown)(rem),
        },
        Err(e) => Err(e),
    }
}

#[deprecated(
    since = "0.11.0",
    note = "Please use the parse_section_content_block_le function instead"
)]
#[inline]
pub fn parse_section_content_block(i: &[u8]) -> IResult<&[u8], Block, PcapError> {
    parse_section_content_block_le(i)
}

/// Parse any block from a section (little-endian)
pub fn parse_section_content_block_le(i: &[u8]) -> IResult<&[u8], Block, PcapError> {
    let (rem, block) = parse_block_le(i)?;
    match block {
        Block::SectionHeader(_) => Err(Err::Error(error_position!(i, ErrorKind::Tag))),
        _ => Ok((rem, block)),
    }
}

/// Parse any block from a section (big-endian)
pub fn parse_section_content_block_be(i: &[u8]) -> IResult<&[u8], Block, PcapError> {
    let (rem, block) = parse_block_be(i)?;
    match block {
        Block::SectionHeader(_) => Err(Err::Error(error_position!(i, ErrorKind::Tag))),
        _ => Ok((rem, block)),
    }
}

/// Parse one section (little or big endian)
pub fn parse_section(i: &[u8]) -> IResult<&[u8], Section, PcapError> {
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
pub fn parse_sections(i: &[u8]) -> IResult<&[u8], Vec<Section>, PcapError> {
    many1(complete(parse_section))(i)
}
