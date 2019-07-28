use crate::blocks::{PcapBlock, PcapBlockOwned};
use crate::capture::Capture;
use crate::linktype::Linktype;
use crate::pcap::{parse_pcap_frame, parse_pcap_frame_be, parse_pcap_header, PcapHeader};
use crate::traits::{LegacyPcapBlock, PcapReaderIterator};
use circular::Buffer;
use nom::{self, IResult, Offset};
use std::fmt;
use std::io::Read;

/// Parsing iterator over legacy pcap data (streaming version)
///
/// This iterator a streaming parser based on a circular buffer, so any input providing the `Read`
/// trait can be used.
///
/// The first call to `next` will return the file header. Some information of this header must
/// be stored (for ex. the data link type) to be able to parse following block contents.
/// Following calls to `next` will always return legacy data blocks.
///
/// The size of the circular buffer has to be big enough for at least one complete block. Using a
/// larger value (at least 65k) is advised to avoid frequent reads and buffer shifts.
///
/// ```rust
/// # extern crate nom;
/// # extern crate pcap_parser;
/// use pcap_parser::*;
/// use pcap_parser::traits::PcapReaderIterator;
/// use nom::ErrorKind;
/// use std::fs::File;
/// use std::io::Read;
///
/// # fn main() {
/// # let path = "assets/ntp.pcap";
/// let mut file = File::open(path).unwrap();
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
///         Err(ErrorKind::Eof) => break,
///         Err(e) => panic!("error while reading: {:?}", e),
///     }
/// }
/// println!("num_blocks: {}", num_blocks);
/// # }
/// ```
pub struct LegacyPcapReader<R>
where
    R: Read,
{
    header: PcapHeader,
    reader: R,
    buffer: Buffer,
    header_sent: bool,
}

impl<R> LegacyPcapReader<R>
where
    R: Read,
{
    pub fn new(capacity: usize, mut reader: R) -> Result<LegacyPcapReader<R>, nom::ErrorKind<u32>> {
        let mut buffer = Buffer::with_capacity(capacity);
        let sz = reader
            .read(buffer.space())
            .or(Err(nom::ErrorKind::Custom(0)))?;
        buffer.fill(sz);
        let (_rem, header) = parse_pcap_header(buffer.data()).map_err(|e| e.into_error_kind())?;
        // do not consume
        Ok(LegacyPcapReader {
            header,
            reader,
            buffer,
            header_sent: false,
        })
    }
    pub fn from_buffer(
        mut buffer: Buffer,
        mut reader: R,
    ) -> Result<LegacyPcapReader<R>, nom::ErrorKind<u32>> {
        let sz = reader
            .read(buffer.space())
            .or(Err(nom::ErrorKind::Custom(0)))?;
        buffer.fill(sz);
        let (_rem, header) = parse_pcap_header(buffer.data()).map_err(|e| e.into_error_kind())?;
        // do not consume
        Ok(LegacyPcapReader {
            header,
            reader,
            buffer,
            header_sent: false,
        })
    }
}

impl<R> PcapReaderIterator<R> for LegacyPcapReader<R>
where
    R: Read,
{
    fn next(&mut self) -> Result<(usize, PcapBlockOwned), nom::ErrorKind<u32>> {
        if !self.header_sent {
            self.header_sent = true;
            return Ok((
                self.header.size(),
                PcapBlockOwned::from(self.header.clone()),
            ));
        }
        if self.buffer.available_data() == 0 {
            return Err(nom::ErrorKind::Eof);
        }
        let data = self.buffer.data();
        let parse = if self.header.is_bigendian() {
            parse_pcap_frame_be
        } else {
            parse_pcap_frame
        };
        match parse(&data) {
            Ok((rem, b)) => {
                let offset = data.offset(rem);
                Ok((offset, PcapBlockOwned::from(b)))
            }
            Err(e) => Err(e.into_error_kind()),
        }
    }
    fn consume(&mut self, offset: usize) {
        self.buffer.consume(offset);
    }
    fn consume_noshift(&mut self, offset: usize) {
        self.buffer.consume_noshift(offset);
    }
    fn refill(&mut self) -> Result<(), &'static str> {
        self.buffer.shift();
        let sz = self
            .reader
            .read(self.buffer.space())
            .or(Err("refill failed"))?;
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

/// Parsing iterator over legacy pcap data (requires data to be loaded into memory)
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
