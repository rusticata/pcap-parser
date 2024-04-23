use crate::blocks::{PcapBlock, PcapBlockOwned};
use crate::error::PcapError;
use crate::pcapng::*;
use nom::combinator::{complete, map};
use nom::multi::many1;
use nom::{IResult, Needed};
use std::fmt;

#[derive(Default)]
pub(crate) struct CurrentSectionInfo {
    pub(crate) big_endian: bool,
}

/// Parsing iterator over pcap-ng data (requires data to be loaded into memory)
///
/// ```rust
/// use pcap_parser::*;
/// use std::fs::File;
/// use std::io::Read;
///
/// # let path = "assets/test001-le.pcapng";
/// let mut file = File::open(path).unwrap();
/// let mut buffer = Vec::new();
/// file.read_to_end(&mut buffer).unwrap();
/// let mut num_blocks = 0;
/// let capture = PcapNGSlice::from_slice(&buffer).expect("parse file");
/// for _block in capture {
///     num_blocks += 1;
/// }
pub struct PcapNGSlice<'a> {
    info: CurrentSectionInfo,
    // remaining (unparsed) data
    rem: &'a [u8],
}

impl<'a> PcapNGSlice<'a> {
    pub fn from_slice(i: &[u8]) -> Result<PcapNGSlice, nom::Err<PcapError<&[u8]>>> {
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
    type Item = Result<PcapBlockOwned<'a>, nom::Err<PcapError<&'a [u8]>>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rem.is_empty() {
            return None;
        }
        let parse = if self.info.big_endian {
            parse_block_be
        } else {
            parse_block_le
        };
        let r = parse(self.rem).map(|(rem, b)| {
            self.rem = rem;
            if let Block::SectionHeader(ref shb) = b {
                self.info.big_endian = shb.big_endian();
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

/// Iterator over `PcapNGCapture`
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
    pub fn from_file(i: &[u8]) -> Result<PcapNGCapture, PcapError<&[u8]>> {
        // XXX change return type to just an IResult
        match parse_pcapng(i) {
            Ok((_, pcap)) => Ok(pcap),
            Err(nom::Err::Error(e)) | Err(nom::Err::Failure(e)) => Err(e),
            Err(nom::Err::Incomplete(Needed::Size(n))) => Err(PcapError::Incomplete(n.into())),
            Err(nom::Err::Incomplete(Needed::Unknown)) => Err(PcapError::Incomplete(0)),
        }
    }

    pub fn iter(&'a self) -> PcapNGCaptureIterator<'a> {
        PcapNGCaptureIterator { cap: self, idx: 0 }
    }
}

/// Parse the entire file
///
/// Note: this requires the file to be fully loaded to memory.
pub fn parse_pcapng(i: &[u8]) -> IResult<&[u8], PcapNGCapture, PcapError<&[u8]>> {
    map(many1(complete(parse_section)), |sections| PcapNGCapture {
        sections,
    })(i)
}
