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
                s.to_vec()
            },
            Err(e) => panic!("error {:?}", e),
        }
    }
}

/// Data link type
///
/// The link-layer header type specifies the type of headers at the beginning
/// of the packet.
///
/// See [http://www.tcpdump.org/linktypes.html](http://www.tcpdump.org/linktypes.html)
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct Linktype(pub i32);

newtype_enum!{
impl display Linktype {
    NULL = 0,
    ETHERNET = 1,

    RAW = 101,

    LOOP = 108,
    LINUX_SLL = 113,

    // Linux netlink NETLINK NFLOG socket log messages.
    // Use the [`pcap_nflog`]()../pcap_nflog/index.html module to access content.
    NFLOG = 239,
}
}

