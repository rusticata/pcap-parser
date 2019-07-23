use crate::blocks::{PcapBlock, PcapBlockOwned};
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
/// use nom::{ErrorKind, IResult};
/// use std::fs::File;
/// use std::io::{BufReader, Read};
///
/// # fn main() {
/// # let path = "assets/test001-le.pcapng";
/// let mut file = File::open(path).unwrap();
/// let mut num_blocks = 0;
/// let mut reader = PcapNGReader::new(65536, file).expect("PcapNGReader");
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
pub struct PcapNGReader<R>
where
    R: Read,
{
    info: CurrentSectionInfo,
    reader: R,
    buffer: Buffer,
    capacity: usize,
}

impl<R> PcapNGReader<R>
where
    R: Read,
{
    pub fn new(capacity: usize, mut reader: R) -> Result<PcapNGReader<R>, nom::ErrorKind<u32>> {
        let mut buffer = Buffer::with_capacity(capacity);
        let sz = reader
            .read(buffer.space())
            .or(Err(nom::ErrorKind::Custom(0)))?;
        buffer.fill(sz);
        // just check that first block is a valid one
        let (_rem, _shb) =
            parse_sectionheaderblock(buffer.data()).map_err(|e| e.into_error_kind())?;
        let info = CurrentSectionInfo::default();
        // do not consume
        Ok(PcapNGReader {
            info,
            reader,
            buffer,
            capacity,
        })
    }
    pub fn from_buffer(
        mut buffer: Buffer,
        mut reader: R,
    ) -> Result<PcapNGReader<R>, nom::ErrorKind<u32>> {
        let capacity = buffer.capacity();
        let sz = reader
            .read(buffer.space())
            .or(Err(nom::ErrorKind::Custom(0)))?;
        buffer.fill(sz);
        // just check that first block is a valid one
        let (_rem, _shb) =
            parse_sectionheaderblock(buffer.data()).map_err(|e| e.into_error_kind())?;
        let info = CurrentSectionInfo::default();
        // do not consume
        Ok(PcapNGReader {
            info,
            reader,
            buffer,
            capacity,
        })
    }
}

impl<R> PcapReaderIterator<R> for PcapNGReader<R>
where
    R: Read,
{
    fn next(&mut self) -> Result<(usize, PcapBlockOwned), nom::ErrorKind<u32>> {
        if self.buffer.available_data() == 0 {
            return Err(nom::ErrorKind::Eof);
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
            Err(e) => Err(e.into_error_kind()),
        }
    }
    fn consume(&mut self, offset: usize) {
        self.buffer.consume_noshift(offset);
        if self.buffer.position() >= self.capacity / 2 {
            // refill
            self.buffer.shift();
            let sz = self
                .reader
                .read(self.buffer.space())
                .expect("refill failed");
            self.buffer.fill(sz);
        }
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
