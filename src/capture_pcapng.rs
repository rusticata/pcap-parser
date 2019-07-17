use crate::packet::PcapBlock;
use nom::IResult;
use pcapng::*;
use std::fmt;

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
        PcapNGCaptureIterator {
            cap: self,
            idx: 0,
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
