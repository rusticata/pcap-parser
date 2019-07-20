use crate::capture::Capture;
use crate::packet::{Linktype, PcapBlock, PcapBlockOwned};
use crate::pcap::{parse_pcap_frame, parse_pcap_header, PcapHeader};
use crate::traits::LegacyPcapBlock;
use nom;
use nom::IResult;
use std::fmt;

/// Iterator over legacy pcap files
///
/// ```rust
/// # extern crate nom;
/// # extern crate pcap_parser;
/// use pcap_parser::*;
/// use nom::IResult;
/// use std::fs::File;
/// use std::io::Read;
///
/// # fn main() {
/// # let path = "assets/ntp.pcap";
/// let mut file = File::open(path).unwrap();
/// let mut buffer = Vec::new();
/// file.read_to_end(&mut buffer).unwrap();
/// let mut num_blocks = 0;
/// match LegacyPcapSlice::from_slice(&buffer) {
///     Ok(iter) => {
///         println!("Format: PCAP");
///         for _block in iter {
///             num_blocks += 1;
///         }
///         return;
///     },
///     _ => ()
/// }
/// # }
/// ```
pub struct LegacyPcapSlice<'a> {
    pub header: PcapHeader,
    // remaining (unparsed) data
    rem: &'a [u8],
}

impl<'a> LegacyPcapSlice<'a> {
    pub fn from_slice(i: &[u8]) -> Result<LegacyPcapSlice, nom::Err<&[u8]>> {
        let (rem, header) = parse_pcap_header(i)?;
        Ok(LegacyPcapSlice { header, rem })
    }
}

/// Iterator for LegacyPcapSlice. Returns a result so parsing errors are not
/// silently ignored
impl<'a> Iterator for LegacyPcapSlice<'a> {
    type Item = Result<PcapBlockOwned<'a>, nom::Err<&'a [u8]>>;

    fn next(&mut self) -> Option<Result<PcapBlockOwned<'a>, nom::Err<&'a [u8]>>> {
        if self.rem.is_empty() {
            return None;
        }
        let r = parse_pcap_frame(self.rem).map(|(rem, b)| {
            self.rem = rem;
            PcapBlockOwned::from(b)
        });
        Some(r)
    }
}

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

impl<'a> fmt::Debug for PcapCapture<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        writeln!(f, "PcapCapture:")
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
        self.header.network
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
