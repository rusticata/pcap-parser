use winnow::stream::AsBytes;

use super::*;

/// A block from a PcapNG file
#[derive(Debug)]
pub enum Block<I: AsBytes> {
    SectionHeader(SectionHeaderBlock<I>),
    // InterfaceDescription(InterfaceDescriptionBlock<'a>),
    // EnhancedPacket(EnhancedPacketBlock<'a>),
    // SimplePacket(SimplePacketBlock<'a>),
    // NameResolution(NameResolutionBlock<'a>),
    // InterfaceStatistics(InterfaceStatisticsBlock<'a>),
    // SystemdJournalExport(SystemdJournalExportBlock<'a>),
    // DecryptionSecrets(DecryptionSecretsBlock<'a>),
    // ProcessInformation(ProcessInformationBlock<'a>),
    // Custom(CustomBlock<'a>),
    // Unknown(UnknownBlock<'a>),
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
            // Block::InterfaceDescription(_) => IDB_MAGIC,
            // Block::EnhancedPacket(_) => EPB_MAGIC,
            // Block::SimplePacket(_) => SPB_MAGIC,
            // Block::NameResolution(_) => NRB_MAGIC,
            // Block::InterfaceStatistics(_) => ISB_MAGIC,
            // Block::SystemdJournalExport(_) => SJE_MAGIC,
            // Block::DecryptionSecrets(_) => DSB_MAGIC,
            // Block::ProcessInformation(_) => PIB_MAGIC,
            // Block::Custom(cb) => cb.block_type,
            // Block::Unknown(ub) => ub.block_type,
        }
    }
}
