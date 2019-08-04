use crate::blocks::{PcapBlock, PcapBlockOwned};
use crate::error::PcapError;
use crate::pcapng::*;
use crate::traits::PcapReaderIterator;
use circular::Buffer;
use nom::{IResult, Offset};
use std::fmt;
use std::io::Read;

/// Parsing iterator over pcap-ng data (streaming version)
///
/// This iterator a streaming parser based on a circular buffer, so any input providing the `Read`
/// trait can be used.
///
/// The first call to `next` should return the a Section Header Block (SHB), marking the start of a
/// new section.
/// For each section, calls to `next` will return blocks, some of them containing data (SPB, EPB),
/// and others containing information (IDB, NRB, etc.).
///
/// Some information must be stored (for ex. the data link type from the IDB) to be able to parse
/// following block contents. Usually, a list of interfaces must be stored, with the data link type
/// and capture length, for each section. These values are used when parsing Enhanced Packet Blocks
/// (which gives an interface ID - the index, starting from 0) and Simple Packet Blocks (which
/// assume an interface index of 0).
///
/// The size of the circular buffer has to be big enough for at least one complete block. Using a
/// larger value (at least 65k) is advised to avoid frequent reads and buffer shifts.
///
///
/// ```rust
/// # extern crate nom;
/// # extern crate pcap_parser;
/// use pcap_parser::*;
/// use pcap_parser::traits::PcapReaderIterator;
/// use nom::IResult;
/// use nom::error::ErrorKind;
/// use std::fs::File;
/// use std::io::{BufReader, Read};
///
/// # fn main() {
/// # let path = "assets/test001-le.pcapng";
/// let mut file = File::open(path).unwrap();
/// let mut num_blocks = 0;
/// let mut reader = PcapNGReader::new(65536, file).expect("PcapNGReader");
/// let mut if_linktypes = Vec::new();
/// loop {
///     match reader.next() {
///         Ok((offset, block)) => {
///             println!("got new block");
///             num_blocks += 1;
///             match block {
///             PcapBlockOwned::NG(Block::SectionHeader(ref _shb)) => {
///                 // starting a new section, clear known interfaces
///                 if_linktypes = Vec::new();
///             },
///             PcapBlockOwned::NG(Block::InterfaceDescription(ref idb)) => {
///                 if_linktypes.push(idb.linktype);
///             },
///             PcapBlockOwned::NG(Block::EnhancedPacket(ref epb)) => {
///                 assert!((epb.if_id as usize) < if_linktypes.len());
///                 let linktype = if_linktypes[epb.if_id as usize];
///                 #[cfg(feature="data")]
///                 let res = pcap_parser::data::get_packetdata(epb.data, linktype, epb.caplen as usize);
///             },
///             PcapBlockOwned::NG(Block::SimplePacket(ref spb)) => {
///                 assert!(if_linktypes.len() > 0);
///                 let linktype = if_linktypes[0];
///                 let blen = (spb.block_len1 - 16) as usize;
///                 #[cfg(feature="data")]
///                 let res = pcap_parser::data::get_packetdata(spb.data, linktype, blen);
///             },
///             PcapBlockOwned::NG(_) => {
///                 // can be statistics (ISB), name resolution (NRB), etc.
///                 eprintln!("unsupported block");
///             },
///             PcapBlockOwned::Legacy(_)
///             | PcapBlockOwned::LegacyHeader(_) => unreachable!(),
///             }
///             reader.consume(offset);
///         },
///         Err(PcapError::Eof) => break,
///         Err(PcapError::NomError(ErrorKind::Complete)) => {
///             eprintln!("Could not read complete data block.");
///             eprintln!("Hint: the reader buffer size may be too small, or the input file nay be truncated.");
///             break;
///         },
///         Err(e) => panic!("error while reading: {:?}", e),
///     }
/// }
/// println!("num_blocks: {}", num_blocks);
/// # }
/// ```
pub struct PcapNGReader<R>
where
    R: Read,
{
    info: CurrentSectionInfo,
    reader: R,
    buffer: Buffer,
}

impl<R> PcapNGReader<R>
where
    R: Read,
{
    pub fn new(capacity: usize, mut reader: R) -> Result<PcapNGReader<R>, PcapError> {
        let mut buffer = Buffer::with_capacity(capacity);
        let sz = reader.read(buffer.space()).or(Err(PcapError::ReadError))?;
        buffer.fill(sz);
        // just check that first block is a valid one
        let (_rem, _shb) = match parse_sectionheaderblock(buffer.data()) {
            Ok((r, h)) => Ok((r, h)),
            Err(nom::Err::Error(e)) | Err(nom::Err::Failure(e)) => Err(e),
            Err(_) => Err(PcapError::Incomplete),
        }?;
        let info = CurrentSectionInfo::default();
        // do not consume
        Ok(PcapNGReader {
            info,
            reader,
            buffer,
        })
    }
    pub fn from_buffer(mut buffer: Buffer, mut reader: R) -> Result<PcapNGReader<R>, PcapError> {
        let sz = reader.read(buffer.space()).or(Err(PcapError::ReadError))?;
        buffer.fill(sz);
        // just check that first block is a valid one
        let (_rem, _shb) = match parse_sectionheaderblock(buffer.data()) {
            Ok((r, h)) => Ok((r, h)),
            Err(nom::Err::Error(e)) | Err(nom::Err::Failure(e)) => Err(e),
            Err(_) => Err(PcapError::Incomplete),
        }?;
        let info = CurrentSectionInfo::default();
        // do not consume
        Ok(PcapNGReader {
            info,
            reader,
            buffer,
        })
    }
}

impl<R> PcapReaderIterator<R> for PcapNGReader<R>
where
    R: Read,
{
    fn next(&mut self) -> Result<(usize, PcapBlockOwned), PcapError> {
        if self.buffer.available_data() == 0 {
            return Err(PcapError::Eof);
        }
        let data = self.buffer.data();
        let parse = if self.info.big_endian {
            parse_block_be
        } else {
            parse_block
        };
        match parse(data) {
            Ok((rem, b)) => {
                let offset = data.offset(rem);
                match b {
                    Block::SectionHeader(ref shb) => {
                        self.info.big_endian = shb.is_bigendian();
                    }
                    _ => (),
                }
                Ok((offset, PcapBlockOwned::from(b)))
            }
            Err(nom::Err::Error(e)) | Err(nom::Err::Failure(e)) => Err(e),
            Err(_) => Err(PcapError::Incomplete),
        }
    }
    fn consume(&mut self, offset: usize) {
        self.buffer.consume(offset);
    }
    fn consume_noshift(&mut self, offset: usize) {
        self.buffer.consume_noshift(offset);
    }
    fn refill(&mut self) -> Result<(), PcapError> {
        self.buffer.shift();
        let sz = self
            .reader
            .read(self.buffer.space())
            .or(Err(PcapError::ReadError))?;
        self.buffer.fill(sz);
        Ok(())
    }
    fn position(&self) -> usize {
        self.buffer.position()
    }
    fn grow(&mut self, new_size: usize) -> bool {
        self.buffer.grow(new_size)
    }
}

#[derive(Default)]
pub struct CurrentSectionInfo {
    big_endian: bool,
}

/// Parsing iterator over pcap-ng data (requires data to be loaded into memory)
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
    pub fn from_slice(i: &[u8]) -> Result<PcapNGSlice, nom::Err<PcapError>> {
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
    type Item = Result<PcapBlockOwned<'a>, nom::Err<PcapError>>;

    fn next(&mut self) -> Option<Result<PcapBlockOwned<'a>, nom::Err<PcapError>>> {
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
    pub fn from_file(i: &[u8]) -> Result<PcapNGCapture, PcapError> {
        // XXX change return type to just an IResult
        match parse_pcapng(i) {
            Ok((_, pcap)) => Ok(pcap),
            Err(nom::Err::Error(e)) | Err(nom::Err::Failure(e)) => Err(e),
            Err(_) => Err(PcapError::Incomplete),
        }
    }

    pub fn iter(&'a self) -> PcapNGCaptureIterator<'a> {
        PcapNGCaptureIterator { cap: self, idx: 0 }
    }
}

/// Parse the entire file
///
/// Note: this requires the file to be fully loaded to memory.
pub fn parse_pcapng(i: &[u8]) -> IResult<&[u8], PcapNGCapture, PcapError> {
    do_parse!(
        i,
        sections: many1!(complete!(parse_section)) >> (PcapNGCapture { sections })
    )
}
