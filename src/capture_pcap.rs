use crate::blocks::{PcapBlock, PcapBlockOwned};
use crate::capture::Capture;
use crate::error::PcapError;
use crate::linktype::Linktype;
use crate::pcap::{
    parse_pcap_frame, parse_pcap_frame_be, parse_pcap_header, LegacyPcapBlock, PcapHeader,
};
use crate::traits::PcapReaderIterator;
use circular::Buffer;
use nom::combinator::complete;
use nom::multi::many0;
use nom::{IResult, Needed, Offset};
use std::fmt;
use std::io::Read;

/// Parsing iterator over legacy pcap data (streaming version)
///
/// ## Pcap Reader
///
/// This reader is a streaming parser based on a circular buffer, which means memory
/// usage is constant, and that it can be used to parse huge files or infinite streams.
/// It creates an abstraction over any input providing the `Read` trait, and takes care
/// of managing the circular buffer to provide an iterator-like interface.
///
/// The first call to `next` will return the file header. Some information of this header must
/// be stored (for ex. the data link type) to be able to parse following block contents.
/// Following calls to `next` will always return legacy data blocks.
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
/// # let path = "assets/ntp.pcap";
/// let file = File::open(path).unwrap();
/// let mut num_blocks = 0;
/// let mut reader = LegacyPcapReader::new(65536, file).expect("LegacyPcapReader");
/// loop {
///     match reader.next() {
///         Ok((offset, block)) => {
///             println!("got new block");
///             num_blocks += 1;
///             match block {
///                 PcapBlockOwned::LegacyHeader(_hdr) => {
///                     // save hdr.network (linktype)
///                 },
///                 PcapBlockOwned::Legacy(_b) => {
///                     // use linktype to parse b.data()
///                 },
///                 PcapBlockOwned::NG(_) => unreachable!(),
///             }
///             reader.consume(offset);
///         },
///         Err(PcapError::Eof) => break,
///         Err(PcapError::Incomplete(_)) => {
///             reader.refill().unwrap();
///         },
///         Err(e) => panic!("error while reading: {:?}", e),
///     }
/// }
/// println!("num_blocks: {}", num_blocks);
/// ```
pub struct LegacyPcapReader<R>
where
    R: Read,
{
    header: PcapHeader,
    reader: R,
    buffer: Buffer,
    consumed: usize,
    header_sent: bool,
    reader_exhausted: bool,
    parse: LegacyParseFn,
}

type LegacyParseFn = fn(&[u8]) -> IResult<&[u8], LegacyPcapBlock, PcapError<&[u8]>>;

impl<R> LegacyPcapReader<R>
where
    R: Read,
{
    /// Creates a new `LegacyPcapReader<R>` with the provided buffer capacity.
    pub fn new(
        capacity: usize,
        reader: R,
    ) -> Result<LegacyPcapReader<R>, PcapError<&'static [u8]>> {
        let buffer = Buffer::with_capacity(capacity);
        Self::from_buffer(buffer, reader)
    }
    /// Creates a new `LegacyPcapReader<R>` using the provided `Buffer`.
    pub fn from_buffer(
        mut buffer: Buffer,
        mut reader: R,
    ) -> Result<LegacyPcapReader<R>, PcapError<&'static [u8]>> {
        let sz = reader.read(buffer.space()).or(Err(PcapError::ReadError))?;
        buffer.fill(sz);
        let (_rem, header) = match parse_pcap_header(buffer.data()) {
            Ok((r, h)) => Ok((r, h)),
            Err(nom::Err::Error(e)) | Err(nom::Err::Failure(e)) => Err(e.to_owned_vec()),
            Err(nom::Err::Incomplete(Needed::Size(n))) => Err(PcapError::Incomplete(n.into())),
            Err(nom::Err::Incomplete(Needed::Unknown)) => Err(PcapError::Incomplete(0)),
        }?;
        let parse = if header.is_bigendian() {
            parse_pcap_frame_be
        } else {
            parse_pcap_frame
        };
        // do not consume
        Ok(LegacyPcapReader {
            header,
            reader,
            buffer,
            consumed: 0,
            header_sent: false,
            reader_exhausted: false,
            parse,
        })
    }
}

impl<R> PcapReaderIterator for LegacyPcapReader<R>
where
    R: Read,
{
    fn next(&mut self) -> Result<(usize, PcapBlockOwned), PcapError<&'_ [u8]>> {
        if !self.header_sent {
            self.header_sent = true;
            return Ok((
                self.header.size(),
                PcapBlockOwned::from(self.header.clone()),
            ));
        }
        // Return EOF if
        // 1) all bytes have been read
        // 2) no more data is available
        if self.buffer.available_data() == 0
            && (self.buffer.position() == 0 && self.reader_exhausted)
        {
            return Err(PcapError::Eof);
        }
        let data = self.buffer.data();
        match (self.parse)(data) {
            Ok((rem, b)) => {
                let offset = data.offset(rem);
                Ok((offset, PcapBlockOwned::from(b)))
            }
            Err(nom::Err::Error(e)) | Err(nom::Err::Failure(e)) => Err(e),
            Err(nom::Err::Incomplete(n)) => {
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
