use crate::blocks::{PcapBlock, PcapBlockOwned};
use crate::capture::Capture;
use crate::linktype::Linktype;
use crate::pcap::{parse_pcap_frame, parse_pcap_frame_be, parse_pcap_header, PcapHeader};
use crate::traits::{LegacyPcapBlock, PcapReaderIterator};
use nom::{self, IResult, Offset};
use std::fmt;
use std::io::BufRead;

/// Iterator over legacy pcap files (streaming parser over BufRead)
///
/// ```rust
/// # extern crate nom;
/// # extern crate pcap_parser;
/// use pcap_parser::*;
/// use pcap_parser::traits::PcapReaderIterator;
/// use nom::{ErrorKind, IResult};
/// use std::fs::File;
/// use std::io::{BufReader, Read};
///
/// # fn main() {
/// # let path = "assets/ntp.pcap";
/// let mut file = File::open(path).unwrap();
/// let buffered = BufReader::new(file);
/// let mut num_blocks = 0;
/// let mut reader = LegacyPcapReader::new(buffered).expect("LegacyPcapReader");
/// loop {
///     match reader.next() {
///         Ok((offset, _block)) => {
///             println!("got new block");
///             num_blocks += 1;
///             reader.consume(offset);
///         },
///         Err(ErrorKind::Eof) => break,
///         Err(e) => panic!("error while reading: {:?}", e),
///     }
/// }
/// println!("num_blocks: {}", num_blocks);
/// # }
/// ```
pub struct LegacyPcapReader<B>
where
    B: BufRead,
{
    header: PcapHeader,
    reader: B,
}

impl<B> LegacyPcapReader<B>
where
    B: BufRead,
{
    pub fn new(mut reader: B) -> Result<LegacyPcapReader<B>, nom::ErrorKind<u32>> {
        let mut buffer = [0; 24];
        reader
            .read(&mut buffer)
            .or(Err(nom::ErrorKind::Custom(0)))?;
        let (_rem, header) = parse_pcap_header(&buffer).map_err(|e| e.into_error_kind())?;
        Ok(LegacyPcapReader { header, reader })
    }
}

impl<B> PcapReaderIterator<B> for LegacyPcapReader<B>
where
    B: BufRead,
{
    fn next(&mut self) -> Result<(usize, PcapBlockOwned), nom::ErrorKind<u32>> {
        if let Ok(buffer) = self.reader.fill_buf() {
            if buffer.is_empty() {
                return Err(nom::ErrorKind::Eof);
            }
            let parse = if self.header.is_bigendian() {
                parse_pcap_frame_be
            } else {
                parse_pcap_frame
            };
            match parse(&buffer) {
                Ok((rem, b)) => {
                    let offset = buffer.offset(rem);
                    Ok((offset, PcapBlockOwned::from(b)))
                }
                Err(e) => Err(e.into_error_kind()),
            }
        } else {
            Err(nom::ErrorKind::Custom(0))
        }
    }
    fn consume(&mut self, offset: usize) {
        self.reader.consume(offset);
    }
}

/// Iterator over legacy pcap files (requires slice to be loaded into memory)
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
