use crate::blocks::{PcapBlock, PcapBlockOwned};
use crate::error::PcapError;
use crate::pcapng::*;
use crate::traits::PcapReaderIterator;
use circular::Buffer;
use std::fmt;
use std::io::Read;
use winnow::error::{ErrMode, IResult, Needed};
use winnow::multi::many1;
use winnow::stream::Offset;
use winnow::Parser;

/// Parsing iterator over pcap-ng data (streaming version)
///
/// ## Pcap-NG Reader
///
/// This reader is a streaming parser based on a circular buffer, which means memory
/// usage is constant, and that it can be used to parse huge files or infinite streams.
/// It creates an abstraction over any input providing the `Read` trait, and takes care
/// of managing the circular buffer to provide an iterator-like interface.
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
/// **There are precautions to take when reading multiple blocks before consuming data. See
/// [PcapReaderIterator](traits/trait.PcapReaderIterator.html) for details.**
///
/// ## Example
///
/// ```rust
/// use pcap_parser::*;
/// use pcap_parser::traits::PcapReaderIterator;
/// use std::fs::File;
///
/// # let path = "assets/test001-le.pcapng";
/// let file = File::open(path).unwrap();
/// let mut num_blocks = 0;
/// let mut reader = PcapNGReader::new(65536, file).expect("PcapNGReader");
/// let mut if_linktypes = Vec::new();
/// let mut last_incomplete_index = 0;
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
///         Err(PcapError::Incomplete(_)) => {
///             if last_incomplete_index == num_blocks {
///                 eprintln!("Could not read complete data block.");
///                 eprintln!("Hint: the reader buffer size may be too small, or the input file nay be truncated.");
///                 break;
///             }
///             last_incomplete_index = num_blocks;
///             reader.refill().expect("Could not refill reader");
///             continue;
///         },
///         Err(e) => panic!("error while reading: {:?}", e),
///     }
/// }
/// println!("num_blocks: {}", num_blocks);
/// ```
pub struct PcapNGReader<R>
where
    R: Read,
{
    info: CurrentSectionInfo,
    reader: R,
    buffer: Buffer,
    consumed: usize,
    reader_exhausted: bool,
}

impl<R> PcapNGReader<R>
where
    R: Read,
{
    /// Creates a new `PcapNGReader<R>` with the provided buffer capacity.
    pub fn new(capacity: usize, reader: R) -> Result<PcapNGReader<R>, PcapError<&'static [u8]>> {
        let buffer = Buffer::with_capacity(capacity);
        Self::from_buffer(buffer, reader)
    }
    /// Creates a new `PcapNGReader<R>` using the provided `Buffer`.
    pub fn from_buffer(
        mut buffer: Buffer,
        mut reader: R,
    ) -> Result<PcapNGReader<R>, PcapError<&'static [u8]>> {
        let sz = reader.read(buffer.space()).or(Err(PcapError::ReadError))?;
        buffer.fill(sz);
        // just check that first block is a valid one
        let (_rem, _shb) = match parse_sectionheaderblock(buffer.data()) {
            Ok((r, h)) => Ok((r, h)),
            Err(ErrMode::Backtrack(e)) | Err(ErrMode::Cut(e)) => Err(e.to_owned_vec()),
            Err(ErrMode::Incomplete(Needed::Size(n))) => Err(PcapError::Incomplete(n.into())),
            Err(ErrMode::Incomplete(Needed::Unknown)) => Err(PcapError::Incomplete(0)),
        }?;
        let info = CurrentSectionInfo::default();
        // do not consume
        Ok(PcapNGReader {
            info,
            reader,
            buffer,
            consumed: 0,
            reader_exhausted: false,
        })
    }
}

impl<R> PcapReaderIterator for PcapNGReader<R>
where
    R: Read,
{
    fn next(&mut self) -> Result<(usize, PcapBlockOwned), PcapError<&[u8]>> {
        // Return EOF if
        // 1) all bytes have been read
        // 2) no more data is available
        if self.buffer.available_data() == 0
            && (self.buffer.position() == 0 && self.reader_exhausted)
        {
            return Err(PcapError::Eof);
        }
        let data = self.buffer.data();
        let parse = if self.info.big_endian {
            parse_block_be
        } else {
            parse_block_le
        };
        match parse(data) {
            Ok((rem, b)) => {
                let offset = data.offset_to(rem);
                if let Block::SectionHeader(ref shb) = b {
                    self.info.big_endian = shb.big_endian();
                }
                Ok((offset, PcapBlockOwned::from(b)))
            }
            Err(ErrMode::Backtrack(e)) | Err(ErrMode::Cut(e)) => Err(e),
            Err(ErrMode::Incomplete(n)) => {
                if self.reader_exhausted {
                    // expected more bytes but reader is EOF, truncated pcap?
                    Err(PcapError::UnexpectedEof)
                } else {
                    match n {
                        Needed::Size(n) => {
                            if self.buffer.available_data() + usize::from(n)
                                >= self.buffer.capacity()
                            {
                                Err(PcapError::BufferTooSmall)
                            } else {
                                Err(PcapError::Incomplete(n.into()))
                            }
                        }
                        Needed::Unknown => Err(PcapError::Incomplete(0)),
                    }
                }
            }
        }
    }
    fn consume(&mut self, offset: usize) {
        self.consumed += offset;
        self.buffer.consume(offset);
    }
    fn consume_noshift(&mut self, offset: usize) {
        self.consumed += offset;
        self.buffer.consume_noshift(offset);
    }
    fn consumed(&self) -> usize {
        self.consumed
    }
    fn refill(&mut self) -> Result<(), PcapError<&[u8]>> {
        self.buffer.shift();
        let space = self.buffer.space();
        // check if available space is empty, so we can distinguish
        // a read() returning 0 because of EOF or because we requested 0
        if space.is_empty() {
            return Ok(());
        }
        let sz = self.reader.read(space).or(Err(PcapError::ReadError))?;
        self.reader_exhausted = sz == 0;
        self.buffer.fill(sz);
        Ok(())
    }
    fn position(&self) -> usize {
        self.buffer.position()
    }
    fn grow(&mut self, new_size: usize) -> bool {
        self.buffer.grow(new_size)
    }
    fn data(&self) -> &[u8] {
        self.buffer.data()
    }
    fn reader_exhausted(&self) -> bool {
        self.reader_exhausted
    }
}

#[derive(Default)]
pub struct CurrentSectionInfo {
    big_endian: bool,
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
    pub fn from_slice(i: &[u8]) -> Result<PcapNGSlice, ErrMode<PcapError<&[u8]>>> {
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
    type Item = Result<PcapBlockOwned<'a>, ErrMode<PcapError<&'a [u8]>>>;

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
            Err(ErrMode::Backtrack(e)) | Err(ErrMode::Cut(e)) => Err(e),
            Err(ErrMode::Incomplete(Needed::Size(n))) => Err(PcapError::Incomplete(n.into())),
            Err(ErrMode::Incomplete(Needed::Unknown)) => Err(PcapError::Incomplete(0)),
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
    let parser = parse_section.complete_err();
    many1(parser)
        .map(|sections| PcapNGCapture { sections })
        .parse_next(i)
}
