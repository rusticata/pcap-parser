use crate::blocks::{PcapBlock, PcapBlockOwned};
use crate::pcapng::*;
use nom::{IResult, Offset};
use std::fmt;
use std::io::BufRead;

/// Iterator over legacy pcap-ng files (streaming parser over BufRead)
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
/// # let path = "assets/test001-le.pcapng";
/// let mut file = File::open(path).unwrap();
/// let buffered = BufReader::new(file);
/// let mut num_blocks = 0;
/// let mut reader = PcapNGReader::new(buffered).expect("PcapNGReader");
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
pub struct PcapNGReader<B>
where
    B: BufRead,
{
    info: CurrentSectionInfo,
    reader: B,
}

impl<B> PcapNGReader<B>
where
    B: BufRead,
{
    pub fn new(mut reader: B) -> Result<PcapNGReader<B>, nom::ErrorKind<u32>> {
        if let Ok(buffer) = reader.fill_buf() {
            // just check that first block is a valid one
            let (_rem, _shb) =
                parse_sectionheaderblock(&buffer).map_err(|e| e.into_error_kind())?;
            let info = CurrentSectionInfo::default();
            Ok(PcapNGReader { info, reader })
        } else {
            Err(nom::ErrorKind::Custom(0))
        }
    }

    pub fn next(&mut self) -> Result<(usize, PcapBlockOwned), nom::ErrorKind<u32>> {
        if let Ok(buffer) = self.reader.fill_buf() {
            if buffer.is_empty() {
                return Err(nom::ErrorKind::Eof);
            }
            let parse = if self.info.big_endian {
                parse_block_be
            } else {
                parse_block
            };
            match parse(&buffer) {
                Ok((rem, b)) => {
                    let offset = buffer.offset(rem);
                    match b {
                        Block::SectionHeader(ref shb) => {
                            self.info.big_endian = shb.is_bigendian();
                        }
                        _ => (),
                    }
                    Ok((offset, PcapBlockOwned::from(b)))
                }
                Err(e) => Err(e.into_error_kind()),
            }
        } else {
            Err(nom::ErrorKind::Custom(0))
        }
    }
    pub fn consume(&mut self, offset: usize) {
        self.reader.consume(offset);
    }
}

#[derive(Default)]
pub struct CurrentSectionInfo {
    big_endian: bool,
}

/// Iterator over pcap-ng files (requires slice to be loaded into memory)
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

/// Parse the entire file
///
/// Note: this requires the file to be fully loaded to memory.
pub fn parse_pcapng(i: &[u8]) -> IResult<&[u8], PcapNGCapture> {
    do_parse!(
        i,
        sections: many1!(complete!(parse_section)) >> (PcapNGCapture { sections })
    )
}
