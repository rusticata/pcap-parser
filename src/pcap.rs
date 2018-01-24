//! PCAP file format
//!
//! See
//! [https://wiki.wireshark.org/Development/LibpcapFileFormat](https://wiki.wireshark.org/Development/LibpcapFileFormat)
//! for details.

use nom::{IResult,le_u16,le_u32,le_i32};
use cookie_factory::GenError;

use packet::{Linktype,Packet,PacketHeader};
use capture::Capture;

#[derive(Debug,PartialEq)]
pub struct PcapHeader {
    pub magic_number: u32,
    pub version_major: u16,
    pub version_minor: u16,
    pub thiszone: i32,
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

pub struct PcapCapture<'a> {
    pub header: PcapHeader,

    data: &'a [u8],

    current_data: &'a [u8],
}

impl<'a> PcapCapture<'a> {
    pub fn from_file(i: &[u8]) -> Result<PcapCapture,IResult<&[u8],PcapCapture>> {
        match parse_pcap_header(i) {
            IResult::Done(rem, hdr) => Ok(PcapCapture{ header:hdr, data:rem, current_data:rem }),
            IResult::Incomplete(e)  => Err(IResult::Incomplete(e)),
            IResult::Error(e)       => Err(IResult::Error(e)),
        }
    }
}

impl<'a> Capture for PcapCapture<'a> {
    fn get_datalink(&self) -> Linktype {
        Linktype(self.header.network)
    }

    fn rewind(&mut self) {
        self.current_data = self.data;
    }

    fn next(&mut self) -> Option<Packet> {
        match parse_pcap_frame(self.current_data) {
            IResult::Done(rem, packet) => {
                self.current_data = rem;
                Some(packet)
            },
            _ => None,
        }
    }
}



pub fn parse_pcap_header(i: &[u8]) -> IResult<&[u8],PcapHeader> {
    do_parse!(
        i,
        magic:   verify!(le_u32, |x| x == 0xa1b2c3d4 || x == 0xd4c3b2a1) >>
        major:   le_u16 >>
        minor:   le_u16 >>
        zone:    le_i32 >>
        sigfigs: le_u32 >>
        snaplen: le_u32 >>
        network: le_i32 >>
        (
            PcapHeader {
                magic_number: magic,
                version_major: major,
                version_minor: minor,
                thiszone: zone,
                sigfigs: sigfigs,
                snaplen: snaplen,
                network: network
            }
        )
    )
}

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
                    ts_usec: ts_usec,
                    caplen: caplen,
                    len: len
                },
                data: data
            }
        )
    )
}
