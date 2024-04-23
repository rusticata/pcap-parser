use crate::blocks::{PcapBlock, PcapBlockOwned};
use crate::capture::Capture;
use crate::error::PcapError;
use crate::linktype::Linktype;
use crate::pcap::{parse_pcap_frame, parse_pcap_header, LegacyPcapBlock, PcapHeader};
use nom::combinator::complete;
use nom::multi::many0;
use nom::{IResult, Needed};
use std::fmt;

/// Parsing iterator over legacy pcap data (requires data to be loaded into memory)
///
/// ```rust
/// use pcap_parser::*;
/// use std::fs::File;
/// use std::io::Read;
///
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
/// ```
pub struct LegacyPcapSlice<'a> {
    pub header: PcapHeader,
    // remaining (unparsed) data
    rem: &'a [u8],
}

impl<'a> LegacyPcapSlice<'a> {
    pub fn from_slice(i: &[u8]) -> Result<LegacyPcapSlice, nom::Err<PcapError<&[u8]>>> {
        let (rem, header) = parse_pcap_header(i)?;
        Ok(LegacyPcapSlice { header, rem })
    }
}

/// Iterator for LegacyPcapSlice. Returns a result so parsing errors are not
/// silently ignored
impl<'a> Iterator for LegacyPcapSlice<'a> {
    type Item = Result<PcapBlockOwned<'a>, nom::Err<PcapError<&'a [u8]>>>;

    fn next(&mut self) -> Option<Self::Item> {
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
    pub fn from_file(i: &[u8]) -> Result<PcapCapture, PcapError<&[u8]>> {
        match parse_pcap(i) {
            Ok((_, pcap)) => Ok(pcap),
            Err(nom::Err::Error(e)) | Err(nom::Err::Failure(e)) => Err(e),
            Err(nom::Err::Incomplete(Needed::Size(n))) => Err(PcapError::Incomplete(n.into())),
            Err(nom::Err::Incomplete(Needed::Unknown)) => Err(PcapError::Incomplete(0)),
        }
    }
}

impl<'a> fmt::Debug for PcapCapture<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        writeln!(f, "PcapCapture:")
    }
}

/// Iterator over `PcapCapture`
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

    fn iter<'b>(&'b self) -> Box<dyn Iterator<Item = PcapBlock> + 'b> {
        Box::new(LegacyPcapIterator { cap: self, idx: 0 })
    }
}

/// Parse the entire file
///
/// Note: this requires the file to be fully loaded to memory.
pub fn parse_pcap(i: &[u8]) -> IResult<&[u8], PcapCapture, PcapError<&[u8]>> {
    let (i, header) = parse_pcap_header(i)?;
    let (i, blocks) = many0(complete(parse_pcap_frame))(i)?;
    Ok((i, PcapCapture { header, blocks }))
}
