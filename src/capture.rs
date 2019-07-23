use crate::blocks::PcapBlock;
use crate::capture_pcap::LegacyPcapReader;
use crate::capture_pcapng::PcapNGReader;
use crate::linktype::Linktype;
use crate::pcap::parse_pcap_header;
use crate::pcapng::parse_sectionheaderblock;
use crate::traits::PcapReaderIterator;
use circular::Buffer;
use std::io::Read;

/// Generic interface for PCAP or PCAPNG file access
pub trait Capture {
    fn get_datalink(&self) -> Linktype;

    fn get_snaplen(&self) -> u32;

    fn iter<'a>(&'a self) -> Box<Iterator<Item = PcapBlock> + 'a>;
}

/// Get a generic PcapReaderIterator, given a buffered input. The input is probed for pca-ng first,
/// then pcap.
pub fn create_reader<'b, R>(
    capacity: usize,
    mut reader: R,
) -> Result<Box<PcapReaderIterator<R> + 'b>, nom::ErrorKind<u32>>
where
    R: Read + 'b,
{
    let mut buffer = Buffer::with_capacity(capacity);
    let sz = reader
        .read(buffer.space())
        .or(Err(nom::ErrorKind::Custom(0)))?;
    buffer.fill(sz);
    // just check that first block is a valid one
    if let Ok(_) = parse_sectionheaderblock(buffer.data()) {
        PcapNGReader::from_buffer(buffer, reader).map(|r| Box::new(r) as Box<PcapReaderIterator<R>>)
    } else if let Ok(_) = parse_pcap_header(buffer.data()) {
        LegacyPcapReader::from_buffer(buffer, reader)
            .map(|r| Box::new(r) as Box<PcapReaderIterator<R>>)
    } else {
        Err(nom::ErrorKind::Tag)
    }
}
