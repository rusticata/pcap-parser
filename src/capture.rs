use packet::{Linktype,Packet};

pub trait Capture {
    fn get_datalink(&self) -> Linktype;

    fn rewind(&mut self);

    fn next(&mut self) -> Option<Packet>;
}
