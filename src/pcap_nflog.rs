//! NFLOG link layer encapsulation for PCAP
//!
//! Helper module to access content of data stored using NFLOG (239)
//! data link type.
//!
//! See [http://www.tcpdump.org/linktypes/LINKTYPE_NFLOG.html](http://www.tcpdump.org/linktypes/LINKTYPE_NFLOG.html) for details.

use nom::{le_u8,le_u16};
use packet::Packet;

// Defined in linux/netfilter/nfnetlink_log.h
const NFULA_PAYLOAD : u16 = 9;

#[derive(Debug)]
pub struct NflogTlv<'a> {
    pub l: u16,
    pub t: u16,
    pub v: &'a[u8],
}

named!(pub parse_nflog_tlv<NflogTlv>,
    do_parse!(
        l: le_u16 >>
        t: le_u16 >>
        v: take!(l-4) >>
        _padding: cond!(l % 4 != 0,take!(4-(l%4))) >>
        ( NflogTlv{l:l,t:t,v:v} )
    )
);

#[derive(Debug)]
pub struct NflogHdr<'a> {
    pub af: u8,
    pub vers: u8,
    pub res_id: u16,
    pub data: Vec<NflogTlv<'a>>,
}

named!(pub parse_nflog_header<NflogHdr>,
    do_parse!(
        af: le_u8 >>
        v:  le_u8 >>
        id: le_u16 >>
        d:  many0!(complete!(parse_nflog_tlv)) >>
        (
            NflogHdr{
                af: af,
                vers: v,
                res_id: id,
                data: d,
            }
        )
    )
);

pub fn get_data_nflog<'a>(packet: &'a Packet) -> &'a[u8] {
    match parse_nflog_header(packet.data) {
        Ok((_,res)) => {
            match res.data.into_iter().find(|v| v.t == NFULA_PAYLOAD) {
                Some(v) => v.v, // XXX is data padded ?
                None    => panic!("packet with no payload data"),
            }
        },
        e @ _ => panic!("parsing nflog packet header failed: {:?}",e), // XXX panic! really ?!
    }
}

