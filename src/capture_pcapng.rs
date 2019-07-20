use crate::packet::{PcapBlock, PcapBlockOwned};
use crate::pcapng::*;
use nom::IResult;
use std::fmt;

#[derive(Default)]
pub struct CurrentSectionInfo {
    big_endian: bool,
}

/// Iterator over PcapNG files
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
/// # let path = "assets/test001-le.pcapng";
/// let mut file = File::open(path).unwrap();
/// let mut buffer = Vec::new();
/// file.read_to_end(&mut buffer).unwrap();
/// let mut num_blocks = 0;
/// let capture = PcapNGSlice::from_slice(&buffer).expect("parse file");
/// for _block in capture {
///     num_blocks += 1;
/// }
/// # }
pub struct PcapNGSlice<'a> {
    info: CurrentSectionInfo,
    // remaining (unparsed) data
    rem: &'a [u8],
}

impl<'a> PcapNGSlice<'a> {
    pub fn from_slice(i: &[u8]) -> Result<PcapNGSlice, nom::Err<&[u8]>> {
        // just check that first block is a valid one
        let (_rem, _shb) = parse_sectionheaderblock(i)?;
        let info = CurrentSectionInfo::default();
        let rem = i;
        Ok(PcapNGSlice { info, rem })
    }
}

/// Iterator for PcapNGSlice. Returns a result so parsing errors are not
/// silently ignored
impl<'a> Iterator for PcapNGSlice<'a> {
    type Item = Result<PcapBlockOwned<'a>, nom::Err<&'a [u8]>>;

    fn next(&mut self) -> Option<Result<PcapBlockOwned<'a>, nom::Err<&'a [u8]>>> {
        if self.rem.is_empty() {
            return None;
        }
        let parse = if self.info.big_endian {
            parse_block_be
        } else {
            parse_block
        };
        let r = parse(self.rem).map(|(rem, b)| {
            self.rem = rem;
            match b {
                Block::SectionHeader(ref shb) => {
                    self.info.big_endian = shb.is_bigendian();
                }
                _ => (),
            }
            PcapBlockOwned::from(b)
        });
        Some(r)
    }
}

/// Generic interface for PCAPNG file access
pub struct PcapNGCapture<'a> {
    pub sections: Vec<Section<'a>>,
}

impl<'a> fmt::Debug for PcapNGCapture<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        writeln!(f, "PcapNGCapture:")
    }
}

// Non-consuming iterator
pub struct PcapNGCaptureIterator<'a> {
    cap: &'a PcapNGCapture<'a>,
    idx: usize,
}

impl<'a> Iterator for PcapNGCaptureIterator<'a> {
    type Item = PcapBlock<'a>;

    fn next(&mut self) -> Option<PcapBlock<'a>> {
        if self.cap.sections.len() != 1 {
            // XXX only one section supported
            unimplemented!();
        }
        self.cap.sections[0].blocks.get(self.idx).map(|b| {
            self.idx += 1;
            PcapBlock::from(b)
        })
    }
}

impl<'a> PcapNGCapture<'a> {
    pub fn from_file(i: &[u8]) -> Result<PcapNGCapture, IResult<&[u8], PcapNGCapture>> {
        // XXX change return type to just an IResult
        match parse_pcapng(i) {
            Ok((_, pcap)) => Ok(pcap),
            e => Err(e),
        }
    }

    pub fn iter(&'a self) -> PcapNGCaptureIterator<'a> {
        PcapNGCaptureIterator { cap: self, idx: 0 }
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

// impl<'a> Capture for PcapNGCapture<'a> {
//     fn get_datalink(&self) -> Linktype {
//         // assume first linktype is the same
//         assert!(self.sections.len() > 0);
//         let section = &self.sections[0];
//         assert!(section.interfaces.len() > 0);
//         let interface = &section.interfaces[0];
//         Linktype(interface.header.linktype as i32)
//     }
//
//     fn get_snaplen(&self) -> u32 {
//         // assume first linktype is the same
//         assert!(self.sections.len() > 0);
//         let section = &self.sections[0];
//         assert!(section.interfaces.len() > 0);
//         let interface = &section.interfaces[0];
//         interface.header.snaplen
//     }
//
//     fn iter_packets<'b>(&'b self) -> Box<Iterator<Item=Packet> + 'b> {
//         Box::new(self.iter())
//     }
// }

/// Parse the entire file
///
/// Note: this requires the file to be fully loaded to memory.
pub fn parse_pcapng(i: &[u8]) -> IResult<&[u8], PcapNGCapture> {
    // XXX wrong
    // XXX file must be parsed iteratively, dealing with endianness
    do_parse!(
        i,
        sections: many1!(complete!(parse_section)) >> (PcapNGCapture { sections })
    )
}
