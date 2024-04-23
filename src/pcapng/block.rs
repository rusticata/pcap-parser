use nom::bytes::streaming::take;
use nom::combinator::map;
use nom::error::*;
use nom::number::streaming::{be_u32, le_u32};
use nom::{Err, IResult};

use crate::endianness::PcapEndianness;
use crate::PcapError;

use super::*;

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

pub(crate) trait PcapNGBlockParser<'a, En: PcapEndianness, O: 'a> {
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

/// Create a block parser function, given the parameters (block object and endianness)
pub(crate) fn ng_block_parser<'a, P, En, O, E>() -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], O, E>
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
