//! PCAPNG file format
//!
//! See [https://github.com/pcapng/pcapng](https://github.com/pcapng/pcapng) for details.

use nom::{IResult,Err,ErrorKind,le_u16,le_u32,le_i64};

use capture::Capture;
use packet::{Packet,PacketHeader,Linktype};

use byteorder::{ByteOrder,LittleEndian};

use std::fmt;

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

#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct OptionCode(pub u16);

newtype_enum!{
impl display OptionCode {
    EndOfOpt = 0,
    Comment = 1,
    ShbHardware = 2,
    ShbOs = 3,
    ShbUserAppl = 4,
    IfTsresol = 9,
    IfTsoffset = 14,
}
}

#[derive(Debug)]
pub struct PcapNGCapture<'a> {
    pub sections: Vec<Section<'a>>,
}

#[derive(Debug,PartialEq)]
pub enum Block<'a> {
    SectionHeader(SectionHeaderBlock<'a>),
    InterfaceDescription(InterfaceDescriptionBlock<'a>),
    EnhancedPacket(EnhancedPacketBlock<'a>),
    SimplePacket(SimplePacketBlock<'a>),
    InterfaceStatistics(InterfaceStatisticsBlock<'a>),
    Unknown(UnknownBlock<'a>)
}

#[derive(Debug, PartialEq)]
pub struct Section<'a> {
    pub header: SectionHeaderBlock<'a>,

    pub interfaces: Vec<Interface<'a>>,
}

#[derive(PartialEq)]
pub struct Interface<'a> {
    pub header: InterfaceDescriptionBlock<'a>,

    pub blocks: Vec<Block<'a>>,

    // extracted values
    pub if_tsresol: u8,
    pub if_tsoffset: u64
}

/// Compact (debug) display of interface and blocks
impl<'a> fmt::Debug for Interface<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        writeln!(f, "Interface:")?;
        writeln!(f, "    header: {:?}", self.header)?;
        for b in self.blocks.iter() {
            let s = match b {
                &Block::EnhancedPacket(ref e) => format!("EPB(if={}, caplen={}, origlen={})", e.if_id, e.caplen, e.origlen),
                &Block::SimplePacket(ref e)   => format!("SPB(origlen={})", e.origlen),
                &Block::Unknown(ref e)        => format!("Unk(type={}, blocklen={})", e.block_type, e.block_len1),
                _ => format!(""),
            };
            writeln!(f, "    {}", s)?;
        }
        Ok(())
    }
}

impl<'a> Section<'a> {
    pub fn iter_packets(&'a self) -> SectionPacketIterator<'a> {
        SectionPacketIterator{ section: self, index_interface: 0, index_block: 0 }
    }

    pub fn iter_interfaces(&'a self) -> SectionInterfaceIterator<'a> {
        SectionInterfaceIterator{ section: self, index_interface: 0 }
    }

    /// Get a vector of packets, sorted by timestamp
    /// The vector is allocated.
    ///
    /// Choose `sort_by` because it is likely the packets are already almost sorted,
    /// or are series of almost-soted packets (if there are multiple interfaces)
    pub fn sorted_by_timestamp(&self) -> Vec<Packet> {
        let mut v : Vec<_> = self.iter_packets().collect();
        v.sort_by(
            |a, b|
            a.header.ts_sec.cmp(&b.header.ts_sec).then(a.header.ts_usec.cmp(&b.header.ts_usec))
            );
        v
    }
}

// Non-consuming iterator
pub struct SectionInterfaceIterator<'a> {
    section: &'a Section<'a>,
    index_interface: usize,
}

impl<'a> Iterator for SectionInterfaceIterator<'a> {
    type Item = &'a Interface<'a>;

    fn next(&mut self) -> Option<&'a Interface<'a>> {
        if self.index_interface < self.section.interfaces.len() {
            let idx = self.index_interface;
            self.index_interface += 1;
            Some(&self.section.interfaces[idx])
        } else {
            None
        }
    }
}

// Non-consuming iterator
pub struct SectionPacketIterator<'a> {
    section: &'a Section<'a>,
    index_interface: usize,
    index_block: usize
}

impl<'a> Iterator for SectionPacketIterator<'a> {
    type Item = Packet<'a>;

    fn next(&mut self) -> Option<Packet<'a>> {
        for interface in &self.section.interfaces[self.index_interface..] {
            for block in &interface.blocks[self.index_block..] {
                self.index_block += 1;
                match packet_of_block(interface, block) {
                    Some(pkt) => return Some(pkt),
                    None      => (),
                }
            }
            self.index_block = 0;
            self.index_interface += 1;
        }
        None
    }
}

impl<'a> Interface<'a> {
    pub fn iter_packets(&'a self) -> InterfacePacketIterator<'a> {
        InterfacePacketIterator{ interface: self, index_block: 0 }
    }
}

// Non-consuming iterator
pub struct InterfacePacketIterator<'a> {
    interface: &'a Interface<'a>,
    index_block: usize
}

impl<'a> Iterator for InterfacePacketIterator<'a> {
    type Item = Packet<'a>;

    fn next(&mut self) -> Option<Packet<'a>> {
        for block in &self.interface.blocks[self.index_block..] {
            self.index_block += 1;
            match packet_of_block(self.interface, block) {
                Some(pkt) => return Some(pkt),
                None      => (),
            }
        }
        None
    }
}

fn packet_of_block<'a>(interface: &'a Interface, block: &'a Block) -> Option<Packet<'a>> {
    match block {
        &Block::EnhancedPacket(ref b) => {
            let if_tsoffset = interface.if_tsoffset;
            let if_tsresol = interface.if_tsresol;
            let ts_mode = if_tsresol & 0x70;
            let unit =
                if ts_mode == 0 { 10u64.pow(if_tsresol as u32) }
                else { 2u64.pow((if_tsresol & !0x70) as u32) };
            let ts : u64 = ((b.ts_high as u64) << 32) | (b.ts_low as u64);
            let ts_sec = (if_tsoffset + (ts / unit)) as u32;
            let ts_usec = (ts % unit) as u32;
            Some(
                Packet{
                    header: PacketHeader{
                        ts_sec: ts_sec,
                        ts_usec: ts_usec,
                        caplen: b.caplen,
                        len: b.origlen
                    },
                    data: b.data
                }
            )
        },
        // e => println!("unknown: {:?}", e),
        _ => None,
    }
}

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

impl<'a> Capture for PcapNGCapture<'a> {
    fn get_datalink(&self) -> Linktype {
        // assume first linktype is the same
        assert!(self.sections.len() > 0);
        let section = &self.sections[0];
        assert!(section.interfaces.len() > 0);
        let interface = &section.interfaces[0];
        Linktype(interface.header.linktype as i32)
    }

    fn get_snaplen(&self) -> u32 {
        // assume first linktype is the same
        assert!(self.sections.len() > 0);
        let section = &self.sections[0];
        assert!(section.interfaces.len() > 0);
        let interface = &section.interfaces[0];
        interface.header.snaplen
    }

    fn iter_packets<'b>(&'b self) -> Box<Iterator<Item=Packet> + 'b> {
        Box::new(self.iter())
    }
}




/// true only if n is a power of 2
macro_rules! align_n2 {
    ($x:expr, $n:expr) => ( ($x + ($n - 1)) & !($n - 1) );
}

macro_rules! align32 {
    ($x:expr) => ( align_n2!($x, 4u32) );
}


// Non-consuming iterator
pub struct PcapNGCaptureIterator<'a> {
    pcap: &'a PcapNGCapture<'a>,
    index_section: usize,
    it: SectionPacketIterator<'a>,
}

impl<'a> PcapNGCapture<'a> {
    pub fn from_file(i: &[u8]) -> Result<PcapNGCapture,IResult<&[u8],PcapNGCapture>> { // XXX change return type to just an IResult
        match parse_pcapng(i) {
            Ok((_, pcap))  => Ok(pcap),
            e              => Err(e)
        }
    }

    pub fn iter(&'a self) -> PcapNGCaptureIterator<'a> {
        assert!(self.sections.len() > 0);
        PcapNGCaptureIterator{
            pcap: self,
            index_section: 0,
            it: self.sections[0].iter_packets()
        }
    }
}

// XXX IntoIterator seems to generate only consuming iterators, or I don't understand how to use it

// impl<'a> IntoIterator for PcapNGCapture<'a> {
//     type Item = Packet<'a>;
//     type IntoIter = PcapNGCaptureIterator<'a>;
// 
//     fn into_iter(self) -> Self::IntoIter {
//         PcapNGCaptureIterator{ pcap: self, index: 0 }
//     }
// }

impl<'a> Iterator for PcapNGCaptureIterator<'a> {
    type Item = Packet<'a>;

    fn next(&mut self) -> Option<Packet<'a>> {
        loop {
            match self.it.next() {
                Some(p) => { return Some(p); },
                _       => (),
            }
            self.index_section += 1;
            if self.index_section >= self.pcap.sections.len() { break; }
            self.it = self.pcap.sections[self.index_section].iter_packets();
        }
        None
    }
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

pub fn parse_sectionheaderblock(i: &[u8]) -> IResult<&[u8],SectionHeaderBlock> {
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

pub fn parse_sectionheader(i: &[u8]) -> IResult<&[u8],Block> {
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
                  Block::SectionHeader(SectionHeaderBlock{
                      block_type: magic,
                      block_len1: len1,
                      bom: bom,
                      major_version: major,
                      minor_version: minor,
                      section_len: slen,
                      options: options.unwrap_or(Vec::new()),
                      block_len2: len2
                  })
              )
    )
}

pub fn parse_interfacedescriptionblock(i: &[u8]) -> IResult<&[u8],InterfaceDescriptionBlock> {
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

pub fn parse_interfacedescription(i: &[u8]) -> IResult<&[u8],Block> {
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
                  Block::InterfaceDescription(InterfaceDescriptionBlock{
                      block_type: magic,
                      block_len1: len1,
                      linktype: linktype,
                      reserved: reserved,
                      snaplen: snaplen,
                      options: options.unwrap_or(Vec::new()),
                      block_len2: len2
                  })
              )
    )
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

pub fn parse_enhancedpacketblock(i: &[u8]) -> IResult<&[u8],Block> {
    do_parse!(i,
                         verify!(le_u32, |x:u32| x == EPB_MAGIC) >>
              len1:      verify!(le_u32, |val:u32| val >= 32) >>
              if_id:     le_u32 >>
              ts_high:   le_u32 >>
              ts_low:    le_u32 >>
              caplen:    verify!(le_u32, |x| x < ::std::u32::MAX - 4) >>
              origlen:   le_u32 >>
              al_len:    value!(align32!(caplen)) >>
              data:      take!(al_len) >>
              options:   cond!(
                    len1 > 32 + al_len,
                    flat_map!(
                        take!(len1 - (32 + al_len)),
                        many0!(complete!(parse_option))
                        )
                  ) >>
              len2:      verify!(le_u32, |x:u32| x == len1) >>
              (
                  Block::EnhancedPacket(EnhancedPacketBlock{
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
              )
    )
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

pub fn parse_block(i: &[u8]) -> IResult<&[u8],Block> {
    match peek!(i, le_u32) {
        Ok((rem, id)) => {
            match id {
                SHB_MAGIC => parse_sectionheader(rem),
                IDB_MAGIC => parse_interfacedescription(rem),
                SPB_MAGIC => parse_simplepacketblock(rem),
                EPB_MAGIC => parse_enhancedpacketblock(rem),
                IFS_MAGIC => parse_interfacestatisticsblock(rem),
                _         => parse_unknownblock(rem)
            }
        },
        Err(e)        => Err(e)
    }
}

pub fn parse_section(i: &[u8]) -> IResult<&[u8],Section> {
    do_parse!(
        i,
        shb: parse_sectionheaderblock >>
        ifs: many0!(complete!(parse_interface)) >>
        ({
            Section {
                header: shb,
                interfaces: ifs,
            }
        })
    )
}

pub fn parse_interface(i: &[u8]) -> IResult<&[u8],Interface> {
    do_parse!(
        i,
        idb: parse_interfacedescriptionblock >>
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

pub fn parse_pcapng(i: &[u8]) -> IResult<&[u8],PcapNGCapture> {
    do_parse!(
        i,
        sections: many1!(complete!(parse_section)) >>
        (
            PcapNGCapture{
                sections: sections,
            }
        )
    )
}
