use crate::capture::Capture;
use crate::packet::{Linktype, PcapBlock};
use crate::pcap::{parse_pcap_frame, parse_pcap_header, PcapHeader};
use crate::traits::LegacyPcapBlock;
use nom::IResult;

/// Generic interface for PCAP file access
pub struct PcapCapture<'a> {
    pub header: PcapHeader,

    pub blocks: Vec<LegacyPcapBlock<'a>>,
}

impl<'a> PcapCapture<'a> {
    pub fn from_file(i: &[u8]) -> Result<PcapCapture, IResult<&[u8], PcapCapture>> {
        match parse_pcap(i) {
            Ok((_, pcap)) => Ok(pcap),
            e => Err(e),
        }
    }
}

pub struct LegacyPcapIterator<'a> {
    cap: &'a PcapCapture<'a>,
    idx: usize,
}

impl<'a> Iterator for LegacyPcapIterator<'a> {
    type Item = PcapBlock<'a>;

    fn next(&mut self) -> Option<PcapBlock<'a>> {
        self.cap.blocks.get(self.idx).map(|b| {
            self.idx += 1;
            PcapBlock::from(b)
        })
    }
}

impl<'a> Capture for PcapCapture<'a> {
    fn get_datalink(&self) -> Linktype {
        Linktype(self.header.network)
    }

    fn get_snaplen(&self) -> u32 {
        self.header.snaplen
    }

    fn iter<'b>(&'b self) -> Box<Iterator<Item = PcapBlock> + 'b> {
        Box::new(LegacyPcapIterator { cap: self, idx: 0 })
    }
}

/// Parse the entire file
///
/// Note: this requires the file to be fully loaded to memory.
pub fn parse_pcap(i: &[u8]) -> IResult<&[u8], PcapCapture> {
    do_parse! {
        i,
        hdr:    parse_pcap_header >>
        blocks: many0!(complete!(parse_pcap_frame)) >>
        (
            PcapCapture{
                header: hdr,
                blocks: blocks
            }
        )
    }
}
