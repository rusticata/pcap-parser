use circular::Buffer;
use std::io::Read;
use winnow::error::{ErrMode, Needed};
use winnow::stream::Offset;
use winnow::IResult;

use super::parser::*;
use super::{LegacyPcapBlock, PcapHeader};
use crate::new::blocks::PcapBlockOwned;
use crate::new::reader::*;
use crate::utils::wrap_partial;
use crate::PcapError;

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

type LegacyParseFn = fn(&[u8]) -> IResult<&[u8], LegacyPcapBlock<&[u8]>, PcapError<&[u8]>>;

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
            Err(ErrMode::Backtrack(e)) | Err(ErrMode::Cut(e)) => Err(e.to_owned_vec()),
            Err(ErrMode::Incomplete(Needed::Size(n))) => Err(PcapError::Incomplete(n.into())),
            Err(ErrMode::Incomplete(Needed::Unknown)) => Err(PcapError::Incomplete(0)),
        }?;
        let parse = if header.is_bigendian() {
            parse_pcap_frame_be_u8
        } else {
            parse_pcap_frame_u8
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
    fn next(&mut self) -> BlockResult {
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
                let offset = data.offset_to(rem);
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

#[inline]
fn parse_pcap_frame_u8(i: &[u8]) -> IResult<&[u8], LegacyPcapBlock<&[u8]>, PcapError<&[u8]>> {
    wrap_partial(parse_pcap_frame)(i)
}

#[inline]
fn parse_pcap_frame_be_u8(i: &[u8]) -> IResult<&[u8], LegacyPcapBlock<&[u8]>, PcapError<&[u8]>> {
    wrap_partial(parse_pcap_frame_be)(i)
}
