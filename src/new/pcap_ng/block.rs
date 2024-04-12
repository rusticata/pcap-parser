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
    // EnhancedPacket(EnhancedPacketBlock<'a>),
    // NameResolution(NameResolutionBlock<'a>),
    // InterfaceStatistics(InterfaceStatisticsBlock<'a>),
    // SystemdJournalExport(SystemdJournalExportBlock<'a>),
    // DecryptionSecrets(DecryptionSecretsBlock<'a>),
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
            // Block::EnhancedPacket(_) => EPB_MAGIC,
            // Block::NameResolution(_) => NRB_MAGIC,
            // Block::InterfaceStatistics(_) => ISB_MAGIC,
            // Block::SystemdJournalExport(_) => SJE_MAGIC,
            // Block::DecryptionSecrets(_) => DSB_MAGIC,
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
            // EPB_MAGIC => map(parse_enhancedpacketblock_le, Block::EnhancedPacket)(i),
            // NRB_MAGIC => map(parse_nameresolutionblock_le, Block::NameResolution)(i),
            // ISB_MAGIC => map(
            //     parse_interfacestatisticsblock_le,
            //     Block::InterfaceStatistics,
            // )(i),
            // SJE_MAGIC => map(
            //     parse_systemdjournalexportblock_le,
            //     Block::SystemdJournalExport,
            // )(i),
            // DSB_MAGIC => map(parse_decryptionsecretsblock_le, Block::DecryptionSecrets)(i),
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
            // EPB_MAGIC => map(parse_enhancedpacketblock_be, Block::EnhancedPacket)(i),
            // NRB_MAGIC => map(parse_nameresolutionblock_be, Block::NameResolution)(i),
            // ISB_MAGIC => map(
            //     parse_interfacestatisticsblock_be,
            //     Block::InterfaceStatistics,
            // )(i),
            // SJE_MAGIC => map(
            //     parse_systemdjournalexportblock_be,
            //     Block::SystemdJournalExport,
            // )(i),
            // DSB_MAGIC => map(parse_decryptionsecretsblock_be, Block::DecryptionSecrets)(i),
            // CB_MAGIC => map(parse_customblock_be, Block::Custom)(i),
            // DCB_MAGIC => map(parse_dcb_be, Block::Custom)(i),
            // PIB_MAGIC => map(parse_processinformationblock_be, Block::ProcessInformation)(i),
            _ => parse_unknownblock_be.map(Block::Unknown).parse_next(i),
        },
        Err(e) => Err(e),
    }
}
