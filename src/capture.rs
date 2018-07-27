use packet::{Linktype,Packet};

pub trait Capture {
    fn get_datalink(&self) -> Linktype;

    fn get_snaplen(&self) -> u32;

    fn iter_packets<'a>(&'a self) -> Box<Iterator<Item=Packet> + 'a>;
}
