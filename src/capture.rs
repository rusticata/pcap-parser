use crate::blocks::PcapBlock;
use crate::linktype::Linktype;

/// Generic interface for PCAP or PCAPNG file access
pub trait Capture {
    fn get_datalink(&self) -> Linktype;

    fn get_snaplen(&self) -> u32;

    fn iter<'a>(&'a self) -> Box<Iterator<Item = PcapBlock> + 'a>;
}
