//! NFLOG link layer encapsulation for PCAP
//!
//! Helper module to access content of data stored using NFLOG (239)
//! data link type.
//!
//! See <http://www.tcpdump.org/linktypes/LINKTYPE_NFLOG.html> for details.

use crate::data::{PacketData, ETHERTYPE_IPV4, ETHERTYPE_IPV6};
use nom::number::streaming::{be_u16, le_u16, le_u8};
use nom::{complete, cond, do_parse, many0, named, take};

// Defined in linux/netfilter/nfnetlink_log.h
#[derive(Copy, Clone)]
#[repr(u16)]
pub enum NfAttrType {
    /// packet header structure: hardware protocol (2 bytes), nf hook (1 byte), padding (1 byte)
    PacketHdr = 1,
    /// packet mark value from the skbuff for the packet
    Mark = 2,
    /// packet time stamp structure: seconds (8 bytes), microseconds (8 bytes)
    Timestamp = 3,
    /// 32-bit ifindex of the device on which the packet was received, which could be a bridge group
    IfIndexInDev = 4,
    /// 32-bit ifindex of the device on which the packet was sent, which could be a bridge group
    IfIndexOutDev = 5,
    /// 32-bit ifindex of the physical device on which the packet was received, which is not a bridge group
    IfIndexPhysInDev = 6,
    /// 32-bit ifindex of the physical device on which the packet was sent, which is not a bridge group
    IfIndexPhysOutDev = 7,
    /// hardware address structure:
    /// address length (2 bytes), padding (1 byte), address (8 bytes)
    HwAddr = 8,
    /// packet payload following the link-layer header
    Payload = 9,
    /// null-terminated text string
    Prefix = 10,
    /// 32-bit ifindex of the device on which the packet was received, which could be a bridge group
    Uid = 11,
    /// 32-bit sequence number for packets provided by this nflog device
    Seq = 12,
    /// 32-bit sequence number for packets provided by all nflog devices
    SeqGlobal = 13,
    /// 32-bit group ID that owned the socket on which the packet was sent or received
    Gid = 14,
    /// 32-bit Linux ARPHRD_ value for the device associated with the skbuff for the packet
    HwType = 15,
    /// MAC-layer header for the skbuff for the packet
    HwHeader = 16,
    /// length of the MAC-layer header
    HwLen = 17,
    /// conntrack header (nfnetlink_conntrack.h)
    Ct = 18,
    /// enum ip_conntrack_info
    CtInfo = 19,
}

#[derive(Debug)]
pub struct NflogTlv<'a> {
    /// Length of data (including 4 bytes for length and types)
    pub l: u16,
    /// Type of data (see `NfAttrType`)
    pub t: u16,
    /// Data
    pub v: &'a [u8],
}

named! {
    pub parse_nflog_tlv<NflogTlv>,
    do_parse!(
        l: le_u16 >>
        t: le_u16 >>
        v: take!(l-4) >>
        _padding: cond!(l % 4 != 0,take!(4-(l%4))) >>
        ( NflogTlv{l,t,v} )
    )
}

#[derive(Debug)]
pub struct NflogHdr {
    /// Address family
    pub af: u8,
    /// Version (currently: 0)
    pub vers: u8,
    /// Resource ID: nflog group for the packet
    pub res_id: u16,
}

#[derive(Debug)]
pub struct NflogPacket<'a> {
    /// The nflog packet header
    pub header: NflogHdr,
    /// The objects (Type-Length-Value)
    pub data: Vec<NflogTlv<'a>>,
}

named! {
    pub parse_nflog_header<NflogHdr>,
    do_parse!(
        af: le_u8 >>
        v:  le_u8 >>
        id: be_u16 >>
        (
            NflogHdr{
                af,
                vers: v,
                res_id: id,
            }
        )
    )
}

impl<'a> NflogPacket<'a> {
    pub fn get(&self, attr: NfAttrType) -> Option<&NflogTlv> {
        self.data.iter().find(|v| v.t == attr as u16)
    }

    pub fn get_payload(&self) -> Option<&[u8]> {
        self.get(NfAttrType::Payload).map(|tlv| tlv.v)
    }
}

named! {
    pub parse_nflog<NflogPacket>,
    do_parse!(
        header: parse_nflog_header >>
        data:   many0!(complete!(parse_nflog_tlv)) >>
        (
            NflogPacket{ header, data }
        )
    )
}

/// Get packet data for LINKTYPE_NFLOG (239)
///
/// Parse nflog data, and extract only packet payload
///
/// See <http://www.tcpdump.org/linktypes/LINKTYPE_NFLOG.html>
pub fn get_packetdata_nflog(i: &[u8], _caplen: usize) -> Option<PacketData> {
    match parse_nflog(i) {
        Ok((_, res)) => {
            let ethertype = match res.header.af {
                2 => ETHERTYPE_IPV4,
                10 => ETHERTYPE_IPV6,
                _ => 0,
            };
            match res
                .data
                .into_iter()
                .find(|v| v.t == NfAttrType::Payload as u16)
            {
                Some(v) => Some(PacketData::L3(ethertype, v.v)),
                None => None,
            }
        }
        _ => None,
    }
}
