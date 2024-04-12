use rusticata_macros::newtype_enum;

mod block;
mod blockparser;
mod decryption_secrets;
mod enhanced_packet;
mod interface_description;
mod interface_statistics;
mod name_resolution;
mod option;
mod reader;
mod section_header;
mod simple_packet;
mod systemd_journal_export;
mod ts;
mod unknown;

pub use block::*;
pub use decryption_secrets::*;
pub use enhanced_packet::*;
pub use interface_description::*;
pub use interface_statistics::*;
pub use name_resolution::*;
pub use option::*;
pub use reader::*;
pub use section_header::*;
pub use simple_packet::*;
pub use systemd_journal_export::*;
pub use ts::*;
pub use unknown::*;

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
