//! PCAP file format
//!
//! See https://wiki.wireshark.org/Development/LibpcapFileFormat

use cookie_factory::GenError;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Linktype(pub i32);

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
    pub network: u32
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
