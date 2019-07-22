use crate::linktype::Linktype;
use crate::packet::PcapBlock;

/// Generic interface for PCAP or PCAPNG file access
pub trait Capture {
    fn get_datalink(&self) -> Linktype;

    fn get_snaplen(&self) -> u32;

    fn iter<'a>(&'a self) -> Box<Iterator<Item = PcapBlock> + 'a>;
}
