use winnow::combinator::peek;
use winnow::number::{be_u32, le_u32};
use winnow::stream::{AsBytes, Stream, StreamIsPartial};
use winnow::{IResult, Parser};

use super::*;
use crate::PcapError;

/// A block from a PcapNG file
#[derive(Debug)]
pub enum Block<I: AsBytes> {
    SectionHeader(SectionHeaderBlock<I>),
    InterfaceDescription(InterfaceDescriptionBlock<I>),
    SimplePacket(SimplePacketBlock<I>),
    EnhancedPacket(EnhancedPacketBlock<I>),
    NameResolution(NameResolutionBlock<I>),
    InterfaceStatistics(InterfaceStatisticsBlock<I>),
    SystemdJournalExport(SystemdJournalExportBlock<I>),
    DecryptionSecrets(DecryptionSecretsBlock<I>),
    // ProcessInformation(ProcessInformationBlock<'a>),
    // Custom(CustomBlock<'a>),
    Unknown(UnknownBlock<I>),
}

impl<I: AsBytes> Block<I> {
    // /// Returns true if blocks contains a network packet
    // pub fn is_data_block(&self) -> bool {
    //     matches!(self, &Block::EnhancedPacket(_) | &Block::SimplePacket(_))
    // }

    /// Return the normalized magic number of the block
    pub fn magic(&self) -> u32 {
        match self {
            Block::SectionHeader(_) => SHB_MAGIC,
            Block::InterfaceDescription(_) => IDB_MAGIC,
            Block::SimplePacket(_) => SPB_MAGIC,
            Block::EnhancedPacket(_) => EPB_MAGIC,
            Block::NameResolution(_) => NRB_MAGIC,
            Block::InterfaceStatistics(_) => ISB_MAGIC,
            Block::SystemdJournalExport(_) => SJE_MAGIC,
            Block::DecryptionSecrets(_) => DSB_MAGIC,
            // Block::ProcessInformation(_) => PIB_MAGIC,
            // Block::Custom(cb) => cb.block_type,
            Block::Unknown(ub) => ub.block_type,
        }
    }
}

/// Parse any block, as little-endian
///
/// To find which endianess to use, read the section header
/// using `parse_sectionheaderblock`
pub fn parse_block_le<I>(i: I) -> IResult<I, Block<I>, PcapError<I>>
where
    I: Stream<Token = u8, Slice = I> + StreamIsPartial,
    <I as Stream>::Slice: AsBytes,
{
    match peek(le_u32)(i) {
        Ok((i, id)) => match id {
            SHB_MAGIC => parse_sectionheaderblock
                .map(Block::SectionHeader)
                .parse_next(i),
            IDB_MAGIC => parse_interfacedescriptionblock_le
                .map(Block::InterfaceDescription)
                .parse_next(i),
            SPB_MAGIC => parse_simplepacketblock_le
                .map(Block::SimplePacket)
                .parse_next(i),
            EPB_MAGIC => parse_enhancedpacketblock_le
                .map(Block::EnhancedPacket)
                .parse_next(i),
            NRB_MAGIC => parse_nameresolutionblock_le
                .map(Block::NameResolution)
                .parse_next(i),
            ISB_MAGIC => parse_interfacestatisticsblock_le
                .map(Block::InterfaceStatistics)
                .parse_next(i),
            SJE_MAGIC => parse_systemdjournalexportblock_le
                .map(Block::SystemdJournalExport)
                .parse_next(i),
            DSB_MAGIC => parse_decryptionsecretsblock_le
                .map(Block::DecryptionSecrets)
                .parse_next(i),
            // CB_MAGIC => map(parse_customblock_le, Block::Custom)(i),
            // DCB_MAGIC => map(parse_dcb_le, Block::Custom)(i),
            // PIB_MAGIC => map(parse_processinformationblock_le, Block::ProcessInformation)(i),
            _ => parse_unknownblock_le.map(Block::Unknown).parse_next(i),
        },
        Err(e) => Err(e),
    }
}

/// Parse any block, as big-endian
///
/// To find which endianess to use, read the section header
/// using `parse_sectionheaderblock`
pub fn parse_block_be<I>(i: I) -> IResult<I, Block<I>, PcapError<I>>
where
    I: Stream<Token = u8, Slice = I> + StreamIsPartial,
    <I as Stream>::Slice: AsBytes,
{
    match peek(be_u32)(i) {
        Ok((i, id)) => match id {
            SHB_MAGIC => parse_sectionheaderblock_be
                .map(Block::SectionHeader)
                .parse_next(i),
            IDB_MAGIC => parse_interfacedescriptionblock_be
                .map(Block::InterfaceDescription)
                .parse_next(i),
            SPB_MAGIC => parse_simplepacketblock_be
                .map(Block::SimplePacket)
                .parse_next(i),
            EPB_MAGIC => parse_enhancedpacketblock_be
                .map(Block::EnhancedPacket)
                .parse_next(i),
            NRB_MAGIC => parse_nameresolutionblock_be
                .map(Block::NameResolution)
                .parse_next(i),
            ISB_MAGIC => parse_interfacestatisticsblock_be
                .map(Block::InterfaceStatistics)
                .parse_next(i),
            SJE_MAGIC => parse_systemdjournalexportblock_le
                .map(Block::SystemdJournalExport)
                .parse_next(i),
            DSB_MAGIC => parse_decryptionsecretsblock_be
                .map(Block::DecryptionSecrets)
                .parse_next(i),
            // CB_MAGIC => map(parse_customblock_be, Block::Custom)(i),
            // DCB_MAGIC => map(parse_dcb_be, Block::Custom)(i),
            // PIB_MAGIC => map(parse_processinformationblock_be, Block::ProcessInformation)(i),
            _ => parse_unknownblock_be.map(Block::Unknown).parse_next(i),
        },
        Err(e) => Err(e),
    }
}