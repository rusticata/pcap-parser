//! PCAP file format
//!
//! See
//! [https://wiki.wireshark.org/Development/LibpcapFileFormat](https://wiki.wireshark.org/Development/LibpcapFileFormat)
//! for details.
//!
//! There are 2 main ways of parsing a PCAP file. The first method is to use
//! [`parse_pcap`](fn.parse_pcap.html). This method requires to load the entire
//! file to memory, and thus may not be good for large files.
//!
//! The [`PcapCapture`](struct.PcapCapture.html) implements the
//! [`Capture`](../trait.Capture.html) trait to provide generic methods. However,
//! this trait also reads the entire file.
//!
//! The second method is to first parse the PCAP header
//! using [`parse_pcap_header`](fn.parse_pcap_header.html), then
//! loop over [`parse_pcap_frame`](fn.parse_pcap_frame.html) to get the data.
//! This can be used in a streaming parser.


use nom::{IResult,be_u16,be_u32,be_i32,le_u16,le_u32,le_i32};
use cookie_factory::GenError;

use packet::{Linktype,Packet,PacketHeader};
use capture::Capture;

/// PCAP global header
#[derive(Debug,PartialEq)]
pub struct PcapHeader {
    /// File format and byte ordering. If equal to `0xa1b2c3d4` then the rest of
    /// the file uses native byte ordering. If `0xd4c3b2a1` (swapped), then all
    /// following fields will have to be swapped too.
    pub magic_number: u32,
    /// Version major number (currently 2)
    pub version_major: u16,
    /// Version minor number (currently 4)
    pub version_minor: u16,
    /// The correction time in seconds between GMT (UTC) and the local timezone of the following packet header timestamps
    pub thiszone: i32,
    /// In theory, the accuracy of time stamps in the capture; in practice, all tools set it to 0
    pub sigfigs: u32,
    /// max len of captured packets, in octets
    pub snaplen: u32,
    /// Data link type
    pub network: i32
}


impl PcapHeader {
    pub fn new() -> PcapHeader {
        PcapHeader{
            magic_number: 0xa1b2c3d4, // native order
            version_major: 2,
            version_minor: 4,
            thiszone: 0,
            sigfigs: 0,
            snaplen: 0,
            network: 1 // default: LINKTYPE_ETHERNET
        }
    }

    pub fn is_bigendian(&self) -> bool {
        self.magic_number == 0xd4c3b2a1
    }

    pub fn to_string(&self) -> Vec<u8> {
        let mut mem : [u8;24] = [0; 24];

        let r = do_gen!(
            (&mut mem,0),
            gen_le_u32!(self.magic_number) >>
            gen_le_u16!(self.version_major) >>
            gen_le_u16!(self.version_minor) >>
            gen_le_i32!(self.thiszone) >>
            gen_le_u32!(self.sigfigs) >>
            gen_le_u32!(self.snaplen) >>
            gen_le_u32!(self.network)
            );
        match r {
            Ok((s,_)) => {
                let mut v = Vec::new();
                v.extend_from_slice(s);
                v
            },
            Err(e) => panic!("error {:?}", e),
        }
    }
}

/// Generic interface for PCAP file access
pub struct PcapCapture<'a> {
    pub header: PcapHeader,

    pub blocks: Vec<Packet<'a>>,
}

impl<'a> PcapCapture<'a> {
    pub fn from_file(i: &[u8]) -> Result<PcapCapture,IResult<&[u8],PcapCapture>> {
        match parse_pcap(i) {
            Ok((_, pcap)) => Ok(pcap),
            e             => Err(e)
        }
    }
}

impl<'a> Capture for PcapCapture<'a> {
    fn get_datalink(&self) -> Linktype {
        Linktype(self.header.network)
    }

    fn get_snaplen(&self) -> u32 {
        self.header.snaplen
    }

    fn iter_packets<'b>(&'b self) -> Box<Iterator<Item=Packet> + 'b> {
        Box::new(self.blocks.iter().cloned())
    }
}




/// Parse the entire file
///
/// Note: this requires the file to be fully loaded to memory.
pub fn parse_pcap(i: &[u8]) -> IResult<&[u8],PcapCapture> {
    do_parse!(
        i,
        hdr:    parse_pcap_header >>
        blocks: many0!(complete!(parse_pcap_frame)) >>
        (
            PcapCapture{
                header: hdr,
                blocks: blocks
            }
        )
    )
}

/// Read the PCAP global header
///
/// The global header contains the PCAP description and options
pub fn parse_pcap_header(i: &[u8]) -> IResult<&[u8],PcapHeader> {
    switch!(i,
        le_u32,
        0xa1b2c3d4 => do_parse!(
            major:   le_u16 >>
            minor:   le_u16 >>
            zone:    le_i32 >>
            sigfigs: le_u32 >>
            snaplen: le_u32 >>
            network: le_i32 >>
            (
                PcapHeader {
                    magic_number: 0xa1b2c3d4,
                    version_major: major,
                    version_minor: minor,
                    thiszone: zone,
                    sigfigs: sigfigs,
                    snaplen: snaplen,
                    network: network
                }
            )
        ) |
        0xd4c3b2a1 => do_parse!(
            major:   be_u16 >>
            minor:   be_u16 >>
            zone:    be_i32 >>
            sigfigs: be_u32 >>
            snaplen: be_u32 >>
            network: be_i32 >>
            (
                PcapHeader {
                    magic_number: 0xd4c3b2a1,
                    version_major: major,
                    version_minor: minor,
                    thiszone: zone,
                    sigfigs: sigfigs,
                    snaplen: snaplen,
                    network: network
                }
            )
        )
    )
}

/// Read a PCAP record header and data
///
/// Each PCAP record starts with a small header, and is followed by packet data.
/// The packet data format depends on the LinkType.
pub fn parse_pcap_frame(i: &[u8]) -> IResult<&[u8],Packet> {
    do_parse!(
        i,
        ts_sec:  le_u32 >>
        ts_usec: le_u32 >>
        caplen:  le_u32 >>
        len:     le_u32 >>
        data:    take!(caplen) >>
        (
            Packet {
                header: PacketHeader {
                    ts_sec: ts_sec,
                    ts_fractional: ts_usec,
                    ts_unit: 1_000_000,
                    caplen: caplen,
                    len: len
                },
                interface: 0,
                data: data
            }
        )
    )
}
/// Read a PCAP record header and data (big-endian)
///
/// Each PCAP record starts with a small header, and is followed by packet data.
/// The packet data format depends on the LinkType.
pub fn parse_pcap_frame_be(i: &[u8]) -> IResult<&[u8],Packet> {
    do_parse!(
        i,
        ts_sec:  be_u32 >>
        ts_usec: be_u32 >>
        caplen:  be_u32 >>
        len:     be_u32 >>
        data:    take!(caplen) >>
        (
            Packet {
                header: PacketHeader {
                    ts_sec: ts_sec,
                    ts_fractional: ts_usec,
                    ts_unit: 1_000_000,
                    caplen: caplen,
                    len: len
                },
                interface: 0,
                data: data
            }
        )
    )
}
