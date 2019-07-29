//! Helper functions to access block contents (depending in linktype)

use crate::linktype::Linktype;
pub use crate::pcap_nflog::*;
use crate::read_u32_e;
use nom::{be_u16, be_u64};

pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_IPV6: u16 = 0x86dd;

/// Contents of a pcap/pcap-ng block. This can be network data, USB, etc.
pub enum PacketData<'a> {
    L2(&'a [u8]),
    L3(u16, &'a [u8]),
    L4(u8, &'a [u8]),

    Unsupported(&'a [u8]),
}

/// Get packet data for LINKTYPE_NULL (0)
///
/// BSD loopback encapsulation; the link layer header is a 4-byte field, in host byte order,
/// containing a value of 2 for IPv4 packets, a value of either 24, 28, or 30 for IPv6 packets, a
/// value of 7 for OSI packets, or a value of 23 for IPX packets. All of the IPv6 values correspond
/// to IPv6 packets; code reading files should check for all of them.
///
/// Note that ``host byte order'' is the byte order of the machine on which the packets are
/// captured; if a live capture is being done, ``host byte order'' is the byte order of the machine
/// capturing the packets, but if a ``savefile'' is being read, the byte order is not necessarily
/// that of the machine reading the capture file.
pub fn get_packetdata_null<'a>(i: &'a [u8], caplen: usize) -> Option<PacketData<'a>> {
    // debug!("data.len: {}, caplen: {}", packet.data.len(), packet.header.caplen);
    if i.len() < caplen || caplen < 4 {
        None
    } else {
        let vers = read_u32_e!(i, false);
        let ethertype = match vers {
            2 => ETHERTYPE_IPV4,
            24 | 28 | 30 => ETHERTYPE_IPV6,
            _ => 0,
        };
        Some(PacketData::L3(ethertype, &i[4..caplen]))
    }
}

/// Get packet data for LINKTYPE_ETHERNET (1)
///
/// IEEE 802.3 Ethernet (10Mb, 100Mb, 1000Mb, and up); the 10MB in the DLT_ name is historical.
pub fn get_packetdata_ethernet<'a>(i: &'a [u8], caplen: usize) -> Option<PacketData<'a>> {
    if i.len() < caplen || caplen == 0 {
        None
    } else {
        Some(PacketData::L2(&i[..caplen]))
    }
}

/// Get packet data for LINKTYPE_RAW (101)
///
/// Raw IP; the packet begins with an IPv4 or IPv6 header, with the "version" field of the header
/// indicating whether it's an IPv4 or IPv6 header.
pub fn get_packetdata_raw<'a>(i: &'a [u8], caplen: usize) -> Option<PacketData<'a>> {
    if i.len() < caplen || caplen == 0 {
        None
    } else {
        let vers = i[0] >> 4;
        let ethertype = match vers {
            4 => ETHERTYPE_IPV4,
            6 => ETHERTYPE_IPV6,
            _ => 0,
        };
        Some(PacketData::L3(ethertype, &i[..caplen]))
    }
}

/// Get packet data for LINKTYPE_LINUX_SLL (113)
///
/// See http://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html
pub fn get_packetdata_linux_sll<'a>(i: &'a [u8], caplen: usize) -> Option<PacketData<'a>> {
    if i.len() < caplen || caplen == 0 {
        None
    } else {
        match parse_sll_header(i) {
            Err(_) => {
                return None;
            }
            Ok((rem, sll)) => {
                match sll.arphrd_type {
                    778 /* ARPHRD_IPGRE */ => Some(PacketData::L4(47, rem)),
                    803 /* ARPHRD_IEEE80211_RADIOTAP */ |
                    824 /* ARPHRD_NETLINK */ => None,
                    _ => Some(PacketData::L3(sll.proto, rem)),
                }
            }
        }
    }
}

struct SLLHeader {
    _packet_type: u16,
    arphrd_type: u16,
    _ll_addr_len: u16,
    _ll_addr: u64,
    proto: u16,
}

named! {
    parse_sll_header<SLLHeader>,
    do_parse!(
        _packet_type: be_u16 >>
        arphrd_type: be_u16 >>
        _ll_addr_len: be_u16 >>
        _ll_addr: be_u64 >>
        proto: be_u16 >>
        (SLLHeader {
                _packet_type,
                arphrd_type,
                _ll_addr_len,
                _ll_addr,
                proto,
            })
    )
}

/// Get packet data for LINKTYPE_IPV4 (228)
///
/// Raw IPv4; the packet begins with an IPv4 header.
pub fn get_packetdata_ipv4<'a>(i: &'a [u8], _caplen: usize) -> Option<PacketData<'a>> {
    Some(PacketData::L3(ETHERTYPE_IPV4, i))
}

/// Get packet data for LINKTYPE_IPV6 (229)
///
/// Raw IPv4; the packet begins with an IPv6 header.
pub fn get_packetdata_ipv6<'a>(i: &'a [u8], _caplen: usize) -> Option<PacketData<'a>> {
    Some(PacketData::L3(ETHERTYPE_IPV6, i))
}

/// Get packet data, depending on linktype.
///
/// Get packet data, depending on linktype.
///
/// Returns None if data could not be extracted (for ex, inner parsing error). If linktype is not
/// supported, `PacketData::Unsupported` is used.
pub fn get_packetdata<'a>(
    i: &'a [u8],
    linktype: Linktype,
    caplen: usize,
) -> Option<PacketData<'a>> {
    match linktype {
        Linktype::NULL => get_packetdata_null(i, caplen),
        Linktype::ETHERNET => get_packetdata_ethernet(i, caplen),
        Linktype::RAW => get_packetdata_raw(i, caplen),
        Linktype::LINUX_SLL => get_packetdata_linux_sll(i, caplen),
        Linktype::IPV4 => get_packetdata_ipv4(i, caplen),
        Linktype::IPV6 => get_packetdata_ipv6(i, caplen),
        Linktype::NFLOG => get_packetdata_nflog(i, caplen),
        _ => Some(PacketData::Unsupported(i)),
    }
}
