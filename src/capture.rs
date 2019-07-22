use crate::blocks::PcapBlock;
use crate::capture_pcap::LegacyPcapReader;
use crate::capture_pcapng::PcapNGReader;
use crate::linktype::Linktype;
use crate::pcap::parse_pcap_header;
use crate::pcapng::parse_sectionheaderblock;
use crate::traits::PcapReaderIterator;
use std::io::BufRead;

/// Generic interface for PCAP or PCAPNG file access
pub trait Capture {
    fn get_datalink(&self) -> Linktype;

    fn get_snaplen(&self) -> u32;

    fn iter<'a>(&'a self) -> Box<Iterator<Item = PcapBlock> + 'a>;
}

/// Get a generic PcapReaderIterator, given a buffered input. The input is probed for pca-ng first,
/// then pcap.
pub fn create_reader<'b, B>(
    mut buffered: B,
) -> Result<Box<PcapReaderIterator<B> + 'b>, nom::ErrorKind<u32>>
where
    B: BufRead + 'b,
{
    if let Ok(buffer) = buffered.fill_buf() {
        // first check for pcapng
        if let Ok(_) = parse_sectionheaderblock(&buffer) {
            PcapNGReader::new(buffered).map(|reader| Box::new(reader) as Box<PcapReaderIterator<B>>)
        } else if let Ok(_) = parse_pcap_header(&buffer) {
            LegacyPcapReader::new(buffered)
                .map(|reader| Box::new(reader) as Box<PcapReaderIterator<B>>)
        } else {
            Err(nom::ErrorKind::Tag)
        }
    } else {
        Err(nom::ErrorKind::Custom(0))
    }
}
