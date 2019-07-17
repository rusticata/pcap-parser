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

use crate::{align32, align_n2};
use crate::packet::PcapBlock;
use crate::traits::EPB;
use nom::{IResult,Err,ErrorKind,be_u16,be_u32,be_i64,le_u16,le_u32,le_i64};
// use packet::{Packet,PacketHeader};
use byteorder::{ByteOrder,LittleEndian};
// use std::fmt;

/// Section Header Block magic
pub const SHB_MAGIC : u32 = 0x0A0D0D0A;
/// Interface Description Block magic
pub const IDB_MAGIC : u32 = 0x00000001;
/// Simple Packet Block magic
pub const SPB_MAGIC : u32 = 0x00000003;
/// Name Resolution Block magic
pub const NMR_MAGIC : u32 = 0x00000004;
/// Interface Statistic Block magic
pub const IFS_MAGIC : u32 = 0x00000005;
/// Enhanced Packet Block magic
pub const EPB_MAGIC : u32 = 0x00000006;

/// Byte Order magic
pub const BOM_MAGIC : u32 = 0x1A2B3C4D;

#[derive(Clone,Copy,Eq,PartialEq)]
pub struct OptionCode(pub u16);

newtype_enum!{
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
    EnhancedPacket(EPB<'a>),
    SimplePacket(SimplePacketBlock<'a>),
    InterfaceStatistics(InterfaceStatisticsBlock<'a>),
    Unknown(UnknownBlock<'a>)
}

/// A Section (including all blocks) from a PcapNG file
pub struct Section<'a> {
    pub header: SectionHeaderBlock<'a>,

    pub blocks: Vec<Block<'a>>,
}

pub struct Interface<'a> {
    pub header: InterfaceDescriptionBlock<'a>,

    pub blocks: Vec<Block<'a>>,

    // extracted values
    pub if_tsresol: u8,
    pub if_tsoffset: u64
}

// /// Compact (debug) display of interface and blocks
// impl<'a> fmt::Debug for Interface<'a> {
//     fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
//         writeln!(f, "Interface:")?;
//         writeln!(f, "    header: {:?}", self.header)?;
//         for b in self.blocks.iter() {
//             let s = match b {
//                 &Block::EnhancedPacket(ref e) => format!("EPB(if={}, caplen={}, origlen={})", e.if_id, e.caplen, e.origlen),
//                 &Block::SimplePacket(ref e)   => format!("SPB(origlen={})", e.origlen),
//                 &Block::Unknown(ref e)        => format!("Unk(type={}, blocklen={})", e.block_type, e.block_len1),
//                 _ => format!(""),
//             };
//             writeln!(f, "    {}", s)?;
//         }
//         Ok(())
//     }
// }

impl<'a> Section<'a> {
    /// Returns an iterator over the section blocks
    pub fn iter(&'a self) -> SectionPacketIterator<'a> {
        SectionPacketIterator{ section: self, index_block: 0 }
    }

    // pub fn iter_interfaces(&'a self) -> SectionInterfaceIterator<'a> {
    //     SectionInterfaceIterator{ section: self, index_interface: 0 }
    // }

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

// // Non-consuming iterator
// pub struct SectionInterfaceIterator<'a> {
//     section: &'a Section<'a>,
//     index_interface: usize,
// }
//
// impl<'a> Iterator for SectionInterfaceIterator<'a> {
//     type Item = &'a Interface<'a>;
//
//     fn next(&mut self) -> Option<&'a Interface<'a>> {
//         if self.index_interface < self.section.interfaces.len() {
//             let idx = self.index_interface;
//             self.index_interface += 1;
//             Some(&self.section.interfaces[idx])
//         } else {
//             None
//         }
//     }
// }

// Non-consuming iterator
pub struct SectionPacketIterator<'a> {
    section: &'a Section<'a>,
    index_block: usize
}

impl<'a> Iterator for SectionPacketIterator<'a> {
    type Item = PcapBlock<'a>;

    fn next(&mut self) -> Option<PcapBlock<'a>> {
        let block = self.section.blocks.get(self.index_block);
        self.index_block += 1;
        block.map(|b| PcapBlock::from(b))
    }
}

// impl<'a> Interface<'a> {
//     pub fn iter_packets(&'a self) -> InterfacePacketIterator<'a> {
//         InterfacePacketIterator{ interface: self, index_block: 0 }
//     }
// }

// // Non-consuming iterator
// pub struct InterfacePacketIterator<'a> {
//     interface: &'a Interface<'a>,
//     index_block: usize
// }
// 
// impl<'a> Iterator for InterfacePacketIterator<'a> {
//     type Item = Packet<'a>;
// 
//     fn next(&mut self) -> Option<Packet<'a>> {
//         for block in &self.interface.blocks[self.index_block..] {
//             self.index_block += 1;
//             match packet_of_block_ref(block, self.interface.if_tsoffset, self.interface.if_tsresol) {
//                 Some(pkt) => return Some(pkt),
//                 None      => (),
//             }
//         }
//         None
//     }
// }

// fn build_ts(ts_high:u32, ts_low:u32, ts_offset:u64, ts_resol:u8) -> (u32,u32,u64) {
//     let if_tsoffset = ts_offset;
//     let if_tsresol = ts_resol;
//     let ts_mode = if_tsresol & 0x70;
//     let unit =
//         if ts_mode == 0 { 10u64.pow(if_tsresol as u32) }
//         else { 2u64.pow((if_tsresol & !0x70) as u32) };
//     let ts : u64 = ((ts_high as u64) << 32) | (ts_low as u64);
//     let ts_sec = (if_tsoffset + (ts / unit)) as u32;
//     let ts_fractional = (ts % unit) as u32;
//     (ts_sec,ts_fractional,unit)
// }

// /// Try to convert a Block to a Packet, consuming the block
// ///
// /// The conversion between a Block and a Packet requires to know the
// /// timestamp offset and resolution (which can be found in the interface description)
// pub fn packet_of_block<'a>(block: Block<'a>, ts_offset:u64, ts_resol:u8) -> Option<Packet<'a>> {
//     match block {
//         Block::EnhancedPacket(ref b) => {
//             let (ts_sec,ts_fractional,ts_unit) = build_ts(b.ts_high, b.ts_low, ts_offset, ts_resol);
//             let header = PacketHeader{
//                 ts_sec,
//                 ts_fractional,
//                 ts_unit,
//                 caplen: b.caplen,
//                 len: b.origlen
//             };
//             let interface = b.if_id;
//             let data = b.data;
//             Some(Packet{header, interface, data})
//         },
//         Block::SimplePacket(ref b) => {
//             let header = PacketHeader{
//                 ts_sec: 0,
//                 ts_fractional: 0,
//                 ts_unit: 0,
//                 caplen: b.data.len() as u32,
//                 len: b.origlen,
//             };
//             let interface = 0;
//             let data = b.data;
//             Some(Packet{header, interface, data})
//         }
//         // e => println!("unknown: {:?}", e),
//         _ => None,
//     }
// }

// /// Try to convert a Block to a Packet, by reference
// ///
// /// The conversion between a Block and a Packet requires to know the
// /// timestamp offset and resolution (which can be found in the interface description)
// pub fn packet_of_block_ref<'a>(block: &'a Block, ts_offset:u64, ts_resol:u8) -> Option<Packet<'a>> {
//     match block {
//         &Block::EnhancedPacket(ref b) => {
//             let (ts_sec,ts_fractional,ts_unit) = build_ts(b.ts_high, b.ts_low, ts_offset, ts_resol);
//             let header = PacketHeader{
//                 ts_sec,
//                 ts_fractional,
//                 ts_unit,
//                 caplen: b.caplen,
//                 len: b.origlen
//             };
//             let interface = b.if_id;
//             let data = b.data;
//             Some(Packet{header, interface, data})
//         },
//         &Block::SimplePacket(ref b) => {
//             let header = PacketHeader{
//                 ts_sec: 0,
//                 ts_fractional: 0,
//                 ts_unit: 0,
//                 caplen: b.data.len() as u32,
//                 len: b.origlen,
//             };
//             let interface = 0;
//             let data = b.data;
//             Some(Packet{header, interface, data})
//         }
//         // e => println!("unknown: {:?}", e),
//         _ => None,
//     }
// }

#[derive(Debug,PartialEq)]
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

#[derive(Debug,PartialEq)]
pub struct InterfaceDescriptionBlock<'a> {
    pub block_type: u32,
    pub block_len1: u32,
    pub linktype: u16,
    pub reserved: u16,
    pub snaplen: u32,
    pub options: Vec<PcapNGOption<'a>>,
    pub block_len2: u32,
}

#[derive(Debug,PartialEq)]
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

#[derive(Debug,PartialEq)]
pub struct SimplePacketBlock<'a> {
    pub block_type: u32,
    pub block_len1: u32,
    /// Original packet length
    pub origlen: u32,
    pub data: &'a [u8],
    pub block_len2: u32,
}

#[derive(Debug,PartialEq)]
pub struct InterfaceStatisticsBlock<'a> {
    pub block_type: u32,
    pub block_len1: u32,
    pub if_id: u32,
    pub ts_high: u32,
    pub ts_low: u32,
    pub options: Vec<PcapNGOption<'a>>,
    pub block_len2: u32,
}

#[derive(Debug,PartialEq)]
pub struct UnknownBlock<'a> {
    pub block_type: u32,
    pub block_len1: u32,
    pub data: &'a [u8],
    pub block_len2: u32,
}

#[derive(Debug,PartialEq)]
pub struct PcapNGOption<'a> {
    pub code: OptionCode,
    pub len: u16,
    pub value: &'a [u8],
}

#[derive(Debug,PartialEq)]
pub struct PcapNGHeader {
    pub magic_number: u32,
    pub version_major: u16,
    pub version_minor: u16,
    pub thiszone: i32,
    pub sigfigs: u32,
    /// max len of captured packets, in octets
    pub snaplen: u32,
    /// Data link type
    pub network: u32
}









pub fn parse_option(i: &[u8]) -> IResult<&[u8],PcapNGOption> {
    do_parse!(i,
              code:  le_u16 >>
              len:   le_u16 >>
              value: take!(align32!(len as u32)) >>
              ( PcapNGOption{
                  code: OptionCode(code),
                  len,
                  value,
              })
    )
}

pub fn parse_option_be(i: &[u8]) -> IResult<&[u8],PcapNGOption> {
    do_parse!(i,
              code:  be_u16 >>
              len:   be_u16 >>
              value: take!(align32!(len as u32)) >>
              ( PcapNGOption{
                  code: OptionCode(code),
                  len,
                  value,
              })
    )
}

pub fn parse_sectionheaderblock_le(i: &[u8]) -> IResult<&[u8],SectionHeaderBlock> {
    do_parse!(i,
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
    )
}

pub fn parse_sectionheaderblock_be(i: &[u8]) -> IResult<&[u8],SectionHeaderBlock> {
    do_parse!(i,
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
    )
}

pub fn parse_sectionheaderblock(i: &[u8]) -> IResult<&[u8],SectionHeaderBlock> {
    peek!(i,tuple!(take!(8),le_u32))
        .and_then(|(rem,(_,bom))| {
            if bom == BOM_MAGIC {
                parse_sectionheaderblock_le(rem)
            } else if bom == u32::from_be(BOM_MAGIC) {
                parse_sectionheaderblock_be(rem)
            } else {
                Err(Err::Error(error_position!(i, ErrorKind::Tag)))
            }
        })
}

pub fn parse_sectionheader(i: &[u8]) -> IResult<&[u8],Block> {
    parse_sectionheaderblock_le(i)
        .map(|(r,b)| (r,Block::SectionHeader(b)))
}

pub fn parse_sectionheader_be(i: &[u8]) -> IResult<&[u8],Block> {
    parse_sectionheaderblock_be(i)
        .map(|(r,b)| (r,Block::SectionHeader(b)))
}

pub fn parse_interfacedescription(i: &[u8]) -> IResult<&[u8],InterfaceDescriptionBlock> {
    do_parse!(i,
              magic:      verify!(le_u32, |x:u32| x == IDB_MAGIC) >>
              len1:       le_u32 >>
              linktype:   le_u16 >>
              reserved:   le_u16 >>
              snaplen:    le_u32 >>
              // options
              options: cond!(
                    len1 > 20,
                    flat_map!(
                        take!(len1 - 20),
                        many0!(complete!(parse_option))
                        )
                  ) >>
              len2:    verify!(le_u32, |x:u32| x == len1) >>
              (
                  InterfaceDescriptionBlock{
                      block_type: magic,
                      block_len1: len1,
                      linktype: linktype,
                      reserved: reserved,
                      snaplen: snaplen,
                      options: options.unwrap_or(Vec::new()),
                      block_len2: len2
                  }
              )
    )
}

pub fn parse_interfacedescriptionblock(i: &[u8]) -> IResult<&[u8],Block> {
    parse_interfacedescription(i)
        .map(|(r,b)| (r,Block::InterfaceDescription(b)))
}

pub fn parse_interfacedescription_be(i: &[u8]) -> IResult<&[u8],InterfaceDescriptionBlock> {
    do_parse!(i,
              magic:      verify!(be_u32, |x:u32| x == IDB_MAGIC) >>
              len1:       be_u32 >>
              linktype:   be_u16 >>
              reserved:   be_u16 >>
              snaplen:    be_u32 >>
              // options
              options: cond!(
                    len1 > 20,
                    flat_map!(
                        take!(len1 - 20),
                        many0!(complete!(parse_option_be))
                        )
                  ) >>
              len2:    verify!(be_u32, |x:u32| x == len1) >>
              (
                  InterfaceDescriptionBlock{
                      block_type: magic,
                      block_len1: len1,
                      linktype: linktype,
                      reserved: reserved,
                      snaplen: snaplen,
                      options: options.unwrap_or(Vec::new()),
                      block_len2: len2
                  }
              )
    )
}

pub fn parse_interfacedescriptionblock_be(i: &[u8]) -> IResult<&[u8],Block> {
    parse_interfacedescription_be(i)
        .map(|(r,b)| (r,Block::InterfaceDescription(b)))
}

pub fn parse_simplepacketblock(i: &[u8]) -> IResult<&[u8],Block> {
    do_parse!(i,
              magic:     verify!(le_u32, |x:u32| x == EPB_MAGIC) >>
              len1:      verify!(le_u32, |val:u32| val >= 32) >>
              origlen:   le_u32 >>
              // XXX if snaplen is < origlen, we MUST use snaplen
              al_len:    value!(align32!(origlen)) >>
              data:      take!(al_len) >>
              len2:      verify!(le_u32, |x:u32| x == len1) >>
              (
                  Block::SimplePacket(SimplePacketBlock{
                      block_type: magic,
                      block_len1: len1,
                      origlen: origlen,
                      data: data,
                      block_len2: len2
                  })
              )
    )
}

pub fn parse_simplepacketblock_be(i: &[u8]) -> IResult<&[u8],Block> {
    do_parse!(i,
              magic:     verify!(be_u32, |x:u32| x == EPB_MAGIC) >>
              len1:      verify!(be_u32, |val:u32| val >= 32) >>
              origlen:   be_u32 >>
              // XXX if snaplen is < origlen, we MUST use snaplen
              al_len:    value!(align32!(origlen)) >>
              data:      take!(al_len) >>
              len2:      verify!(be_u32, |x:u32| x == len1) >>
              (
                  Block::SimplePacket(SimplePacketBlock{
                      block_type: magic,
                      block_len1: len1,
                      origlen: origlen,
                      data: data,
                      block_len2: len2
                  })
              )
    )
}

fn inner_parse_enhancedpacketblock(i: &[u8], big_endian: bool) -> IResult<&[u8], Block> {
    let (_,(magic,block_len)) = match big_endian {
        true => tuple!(i,be_u32,be_u32)?,
        false => tuple!(i,le_u32,le_u32)?,
    };
    error_if!(i, magic != EPB_MAGIC, ErrorKind::Tag)?;
    map_opt!(i,
        take!(block_len),
        |d| EPB::new(d, big_endian).map(|epb| Block::EnhancedPacket(epb))
    )
}

pub fn parse_enhancedpacketblock(i: &[u8]) -> IResult<&[u8], Block> {
    inner_parse_enhancedpacketblock(i, false)
}

pub fn parse_enhancedpacketblock_be(i: &[u8]) -> IResult<&[u8],Block> {
    inner_parse_enhancedpacketblock(i, true)
}

pub fn parse_interfacestatisticsblock(i: &[u8]) -> IResult<&[u8],Block> {
    do_parse!(i,
              magic:      verify!(le_u32, |x:u32| x == IFS_MAGIC) >>
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
    )
}

pub fn parse_interfacestatisticsblock_be(i: &[u8]) -> IResult<&[u8],Block> {
    do_parse!(i,
              magic:      verify!(be_u32, |x:u32| x == IFS_MAGIC) >>
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
    )
}

pub fn parse_unknownblock(i: &[u8]) -> IResult<&[u8],Block> {
    // debug!("Unknown block of ID {:x}", peek!(i, le_u32).unwrap().1);
    do_parse!(i,
              blocktype: le_u32 >>
              len1:      verify!(le_u32, |val:u32| val >= 12) >>
              data:      take!(len1 - 12) >>
              len2:      verify!(le_u32, |x:u32| x == len1) >>
              (
                  Block::Unknown(UnknownBlock{
                      block_type: blocktype,
                      block_len1: len1,
                      data: data,
                      block_len2: len2
                  })
              )
    )
}

pub fn parse_unknownblock_be(i: &[u8]) -> IResult<&[u8],Block> {
    // debug!("Unknown block of ID {:x}", peek!(i, le_u32).unwrap().1);
    do_parse!(i,
              blocktype: be_u32 >>
              len1:      verify!(be_u32, |val:u32| val >= 12) >>
              data:      take!(len1 - 12) >>
              len2:      verify!(be_u32, |x:u32| x == len1) >>
              (
                  Block::Unknown(UnknownBlock{
                      block_type: blocktype,
                      block_len1: len1,
                      data: data,
                      block_len2: len2
                  })
              )
    )
}

/// Parse any block, as little-endian
///
/// To find which endianess to use, read the section header
/// using `parse_sectionheaderblock`
pub fn parse_block(i: &[u8]) -> IResult<&[u8],Block> {
    match peek!(i, le_u32) {
        Ok((rem, id)) => {
            match id {
                SHB_MAGIC => parse_sectionheader(rem),
                IDB_MAGIC => parse_interfacedescriptionblock(rem),
                SPB_MAGIC => parse_simplepacketblock(rem),
                EPB_MAGIC => parse_enhancedpacketblock(rem),
                IFS_MAGIC => parse_interfacestatisticsblock(rem),
                _         => parse_unknownblock(rem)
            }
        },
        Err(e)        => Err(e)
    }
}

/// Parse any block, as big-endian
///
/// To find which endianess to use, read the section header
/// using `parse_sectionheaderblock`
pub fn parse_block_be(i: &[u8]) -> IResult<&[u8],Block> {
    match peek!(i, be_u32) {
        Ok((rem, id)) => {
            match id {
                SHB_MAGIC => parse_sectionheader_be(rem),
                IDB_MAGIC => parse_interfacedescriptionblock_be(rem),
                SPB_MAGIC => parse_simplepacketblock_be(rem),
                EPB_MAGIC => parse_enhancedpacketblock_be(rem),
                IFS_MAGIC => parse_interfacestatisticsblock_be(rem),
                _         => parse_unknownblock_be(rem)
            }
        },
        Err(e)        => Err(e)
    }
}

// XXX nope, there can be packets without interface
// XXX packets are NOT ordered by interface. We should just store the blocks
// XXX store shb as first block
// XXX
// XXX we should store interfaces indexes
pub fn parse_section(i: &[u8]) -> IResult<&[u8], Section> {
    let (rem,shb) = parse_sectionheaderblock(i)?;
    let (rem,blocks) = if shb.is_bigendian() {
        many0!(rem, complete!(parse_section_content_block_be))?
    } else {
        many0!(rem, complete!(parse_section_content_block))?
    };
    let section = Section {
        header: shb,
        blocks,
    };
    Ok((rem, section))
}

pub fn parse_interface(i: &[u8]) -> IResult<&[u8], Interface> {
    do_parse!(
        i,
        idb: parse_interfacedescription >>
        blocks: many0!(complete!(parse_content_block)) >>
        ({
            // XXX extract if_tsoffset and if_tsresol
            let mut if_tsresol : u8 = 6;
            let mut if_tsoffset : u64 = 0;
            for opt in idb.options.iter() {
                match opt.code {
                    OptionCode::IfTsresol  => { if !opt.value.is_empty() { if_tsresol =  opt.value[0]; } },
                    OptionCode::IfTsoffset => { if opt.value.len() >= 8 { if_tsoffset = LittleEndian::read_u64(opt.value); } },
                    _ => (),
                }
            }
            Interface {
                header: idb,
                blocks: blocks,
                if_tsresol: if_tsresol,
                if_tsoffset: if_tsoffset
            }
        })
    )
}

pub fn parse_section_content_block(i: &[u8]) -> IResult<&[u8],Block> {
    match peek!(i, le_u32) {
        Ok((rem, id)) => {
            match id {
                SHB_MAGIC => Err(Err::Error(error_position!(i, ErrorKind::Tag))),
                IDB_MAGIC => call!(rem, parse_interfacedescriptionblock),
                SPB_MAGIC => call!(rem, parse_simplepacketblock),
                EPB_MAGIC => call!(rem, parse_enhancedpacketblock),
                _         => call!(rem, parse_unknownblock)
            }
        },
        Err(e)        => Err(e)
    }
}

pub fn parse_section_content_block_be(i: &[u8]) -> IResult<&[u8], Block> {
    match peek!(i, be_u32) {
        Ok((rem, id)) => {
            match id {
                SHB_MAGIC => Err(Err::Error(error_position!(i, ErrorKind::Tag))),
                IDB_MAGIC => call!(rem, parse_interfacedescriptionblock_be),
                SPB_MAGIC => call!(rem, parse_simplepacketblock_be),
                EPB_MAGIC => call!(rem, parse_enhancedpacketblock_be),
                _         => call!(rem, parse_unknownblock_be)
            }
        },
        Err(e)        => Err(e)
    }
}

pub fn parse_content_block(i: &[u8]) -> IResult<&[u8],Block> {
    match peek!(i, le_u32) {
        Ok((rem, id)) => {
            match id {
                SHB_MAGIC => Err(Err::Error(error_position!(i, ErrorKind::Tag))),
                IDB_MAGIC => Err(Err::Error(error_position!(i, ErrorKind::Tag))),
                SPB_MAGIC => call!(rem, parse_simplepacketblock),
                EPB_MAGIC => call!(rem, parse_enhancedpacketblock),
                _         => call!(rem, parse_unknownblock)
            }
        },
        Err(e)        => Err(e)
    }
}

pub fn traits_parse_enhancedpacketblock(i: &[u8]) -> IResult<&[u8],EPB> {
    let (_,(magic,block_len)) = tuple!(i,le_u32,le_u32)?;
    error_if!(i, magic != EPB_MAGIC, ErrorKind::Tag)?;
    map_opt!(i,
        take!(block_len),
        |d| EPB::new(d, false)
    )
}
