//! PCAPNG file format
//!
//! See [https://github.com/pcapng/pcapng](https://github.com/pcapng/pcapng) for details.

use nom::{IResult,le_u16,le_u32,le_i64};

use packet::{Linktype,Packet,PacketHeader};
use capture::Capture;

use byteorder::{ByteOrder,LittleEndian};

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

#[repr(u16)]
pub enum OptionCode {
    IfTsresol = 9,
    IfTsoffset = 14,
}

#[derive(Debug,PartialEq)]
pub struct PcapNGCapture<'a> {
    pub linktype: Linktype,
    pub snaplen: u32,
    pub blocks: Vec<Block<'a>>,

    if_tsresol : u8,
    if_tsoffset: u64,

    current_index: usize,
}

#[derive(Debug,PartialEq)]
pub enum Block<'a> {
    SectionHeader(SectionHeaderBlock<'a>),
    InterfaceDescription(InterfaceDescriptionBlock<'a>),
    EnhancedPacket(EnhancedPacketBlock<'a>),
    SimplePacket(SimplePacketBlock<'a>),
    Unknown(UnknownBlock<'a>)
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
pub struct UnknownBlock<'a> {
    pub block_type: u32,
    pub block_len1: u32,
    pub data: &'a [u8],
    pub block_len2: u32,
}

#[derive(Debug,PartialEq)]
pub struct PcapNGOption<'a> {
    pub code: u16,
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
    index: usize
}

impl<'a> PcapNGCapture<'a> {
    pub fn from_file(i: &[u8]) -> Result<PcapNGCapture,IResult<&[u8],PcapNGCapture>> {
        match parse_pcapng(i) {
            IResult::Done(_, pcap) => Ok(pcap),
            IResult::Incomplete(e)  => Err(IResult::Incomplete(e)),
            IResult::Error(e)       => Err(IResult::Error(e)),
        }
    }

    pub fn iter(&'a self) -> PcapNGCaptureIterator<'a> {
        PcapNGCaptureIterator{ pcap: self, index: 0 }
    }

    fn build_packet_from_block_at(&self, index: usize) -> Option<Packet<'a>> {
        match self.blocks[index] {
            Block::EnhancedPacket(ref b) => {
                let ts_mode = self.if_tsresol & 0x70;
                let unit =
                    if ts_mode == 0 { 10u64.pow(self.if_tsresol as u32) }
                    else { 2u64.pow((self.if_tsresol & !0x70) as u32) };
                let ts : u64 = ((b.ts_high as u64) << 32) | (b.ts_low as u64);
                let ts_sec = (self.if_tsoffset + (ts / unit)) as u32;
                let ts_usec = (ts % unit) as u32;
                Some(
                    Packet{
                        header: PacketHeader{
                            ts_sec: ts_sec,
                            ts_usec: ts_usec,
                            caplen: b.caplen,
                            len: b.origlen
                        },
                        data: b.data,
                    }
                )
            },
            _ => None,
        }
    }
}

impl<'a> Capture for PcapNGCapture<'a> {
    fn get_datalink(&self) -> Linktype {
        self.linktype
    }

    fn rewind(&mut self) { self.current_index = 0; }

    fn next(&mut self) -> Option<Packet> {
        loop {
            let index = self.current_index;
            if index >= self.blocks.len() { return None; }
            self.current_index += 1;
            match self.build_packet_from_block_at(index) {
                Some(pkt) => {
                    return Some(pkt);
                },
                None => (),
            }
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
        let mut ret = None;
        for b in self.pcap.blocks.iter().skip(self.index) {
            // debug!("iteration: {:?}", b);
            match b {
                &Block::EnhancedPacket(ref b) => {
                    let ts_mode = self.pcap.if_tsresol & 0x70;
                    let unit =
                        if ts_mode == 0 { 10u64.pow(self.pcap.if_tsresol as u32) }
                        else { 2u64.pow((self.pcap.if_tsresol & !0x70) as u32) };
                    let ts : u64 = ((b.ts_high as u64) << 32) | (b.ts_low as u64);
                    let ts_sec = (self.pcap.if_tsoffset + (ts / unit)) as u32;
                    let ts_usec = (ts % unit) as u32;
                    ret = Some(
                            Packet{
                                header: PacketHeader{
                                    ts_sec: ts_sec,
                                    ts_usec: ts_usec,
                                    caplen: b.caplen,
                                    len: b.origlen
                                },
                                data: b.data,
                            }
                        );
                    break;
                },
                _ => (),
            }
            self.index += 1;
        }
        self.index += 1;
        ret
    }
}






pub fn parse_option(i: &[u8]) -> IResult<&[u8],PcapNGOption> {
    do_parse!(i,
              code:  le_u16 >>
              len:   le_u16 >>
              value: take!(align32!(len as u32)) >>
              ( PcapNGOption{
                  code: code,
                  len: len,
                  value: value,
              })
    )
}

pub fn parse_sectionheaderblock(i: &[u8]) -> IResult<&[u8],Block> {
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
                        many0!(parse_option)
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

pub fn parse_interfacedescriptionblock(i: &[u8]) -> IResult<&[u8],Block> {
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
                        many0!(parse_option)
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
                        many0!(parse_option)
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
        IResult::Done(rem, id) => {
            match id {
                SHB_MAGIC => call!(rem, parse_sectionheaderblock),
                IDB_MAGIC => call!(rem, parse_interfacedescriptionblock),
                SPB_MAGIC => call!(rem, parse_simplepacketblock),
                EPB_MAGIC => call!(rem, parse_enhancedpacketblock),
                _         => call!(rem, parse_unknownblock)
            }
        },
        IResult::Incomplete(i) => IResult::Incomplete(i),
        IResult::Error(e)      => IResult::Error(e),
    }
}

pub fn parse_pcapng(i: &[u8]) -> IResult<&[u8],PcapNGCapture> {
    do_parse!(
        i,
        blocks: many0!(parse_block) >>
        ({
            // build object
            let mut pcap = PcapNGCapture{
                linktype: Linktype(-1),
                snaplen: 0,
                blocks: blocks,
                if_tsresol: 6,
                if_tsoffset: 0,
                current_index: 0
            };
            // find IDB block and extract values
            for b in pcap.blocks.iter() {
                match b {
                    &Block::InterfaceDescription(ref idb) => {
                        pcap.linktype = Linktype(idb.linktype as i32);
                        pcap.snaplen = idb.snaplen;
                        // now parse options
                        // debug!("IDB options: {:?}", idb.options);
                        for opt in idb.options.iter() {
                            match opt.code {
                                9 /* OptionCode::IfTsresol */ => { if !opt.value.is_empty() { pcap.if_tsresol = opt.value[0]; } },
                                14 /* OptionCode::IfTsoffset */ => { if opt.value.len() >= 8 { pcap.if_tsoffset = LittleEndian::read_u64(opt.value); } },
                                _ => (),
                            }
                        }
                    },
                    _ => (),
                }
            }
            pcap
        })
    )
}
