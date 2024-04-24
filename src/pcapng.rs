//! PCAPNG file format
//!
//! See <https://github.com/pcapng/pcapng> for details.
//!
//! There are several ways of parsing a PCAPNG file. The first method is to use
//! [`parse_pcapng`]. This method requires to load the entire
//! file to memory, and thus may not be good for large files.
//!
//! The second method is to create a [`PcapNGCapture`] object,
//! which  implements the [`Capture`](crate::Capture) trait to provide generic methods.
//! However, this method also reads the entire file.
//!
//! The third (and prefered) method is to use a [`PcapNGReader`]
//! object.
//!
//! The last method is to manually read the blocks using
//! [`parse_sectionheaderblock`],
//! [`parse_block_le`] and/or
//! [`parse_block_be`].
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

// helpers and common modules
mod block;
mod capture;
mod header;
mod option;
mod reader;
mod section;
mod time;

pub use block::*;
pub use capture::*;
pub use header::*;
pub use option::*;
pub use reader::*;
pub use section::*;
pub use time::*;

/// Blocks
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
mod unknown;

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
