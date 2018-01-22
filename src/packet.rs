use cookie_factory::GenError;

#[derive(Debug,Clone,PartialEq,Eq)]
pub struct Packet<'a> {
    pub header: PacketHeader,
    pub data: &'a [u8],
}

#[derive(Debug,Clone,PartialEq,Eq)]
pub struct PacketHeader {
    pub ts_sec: u32,
    pub ts_usec: u32,
    pub caplen: u32,
    pub len: u32,
}

impl PacketHeader {
    pub fn to_string(&self) -> Vec<u8> {
        let mut mem : [u8;16] = [0; 16];

        let r = do_gen!(
            (&mut mem,0),
            gen_le_u32!(self.ts_sec) >>
            gen_le_u32!(self.ts_usec) >>
            gen_le_u32!(self.caplen) >>
            gen_le_u32!(self.len)
            );
        match r {
            Ok((s,_)) => {
                let mut v = Vec::new();
                v.extend_from_slice(s);
                v
            },
            Err(e) => panic!("error {:?}", e),
        }
    }
}
