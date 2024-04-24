use crate::blocks::PcapBlockOwned;
use crate::error::PcapError;
use crate::pcapng::*;
use crate::traits::PcapReaderIterator;
use circular::Buffer;
use nom::{Needed, Offset};
use std::io::Read;

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
/// [`PcapReaderIterator`] for details.**
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
            Err(nom::Err::Error(e)) | Err(nom::Err::Failure(e)) => Err(e.to_owned_vec()),
            Err(nom::Err::Incomplete(Needed::Size(n))) => Err(PcapError::Incomplete(n.into())),
            Err(nom::Err::Incomplete(Needed::Unknown)) => Err(PcapError::Incomplete(0)),
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
                let offset = data.offset(rem);
                if let Block::SectionHeader(ref shb) = b {
                    self.info.big_endian = shb.big_endian();
                }
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
