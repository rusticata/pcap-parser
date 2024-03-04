//! Helper functions to access block contents (depending in linktype)
//!
//! ## Example
//!
//! ```rust
//! use pcap_parser::data::{get_packetdata, PacketData};
//! use pcap_parser::pcapng::EnhancedPacketBlock;
//! use pcap_parser::Linktype;
//!
//! fn parse_block_content<'a>(
//!     epb: &'a EnhancedPacketBlock<'_>,
//!     linktype: Linktype
//! ) -> Option<()> {
//!     let packet_data =  get_packetdata(epb.data, linktype, epb.caplen as usize)?;
//!     match packet_data {
//!         PacketData::L3(_, _data) => {
//!             // ...
//!         },
//!         _ => println!("Unsupported link type"),
//!     }
//!     Some(())
//! }
//! ```

mod exported_pdu;
mod pcap_nflog;

pub use crate::data::exported_pdu::*;
pub use crate::data::pcap_nflog::*;
use crate::linktype::Linktype;
use crate::read_u32_e;
use nom::number::complete::be_u32;
use nom::number::streaming::{be_u16, be_u64, be_u8};
use nom::IResult;

pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_IPV6: u16 = 0x86dd;

/// Contents of a pcap/pcap-ng block. This can be network data, USB, etc.
#[derive(Clone, Debug)]
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
pub fn get_packetdata_null(i: &[u8], caplen: usize) -> Option<PacketData> {
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
pub fn get_packetdata_ethernet(i: &[u8], caplen: usize) -> Option<PacketData> {
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
pub fn get_packetdata_raw(i: &[u8], caplen: usize) -> Option<PacketData> {
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
/// See <http://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html>
pub fn get_packetdata_linux_sll(i: &[u8], caplen: usize) -> Option<PacketData> {
    if i.len() < caplen || caplen == 0 {
        None
    } else {
        match parse_sll_header(i) {
            Err(_) => None,
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

fn parse_sll_header(i: &[u8]) -> IResult<&[u8], SLLHeader> {
    let (i, _packet_type) = be_u16(i)?;
    let (i, arphrd_type) = be_u16(i)?;
    let (i, _ll_addr_len) = be_u16(i)?;
    let (i, _ll_addr) = be_u64(i)?;
    let (i, proto) = be_u16(i)?;
    let header = SLLHeader {
        _packet_type,
        arphrd_type,
        _ll_addr_len,
        _ll_addr,
        proto,
    };
    Ok((i, header))
}

/// Get packet data for LINKTYPE_LINUX_SLL2 (276)
///
/// See <https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL2.html>
pub fn get_packetdata_linux_sll2(i: &[u8], caplen: usize) -> Option<PacketData> {
    if i.len() < caplen || caplen == 0 {
        None
    } else {
        match parse_sll2_header(i) {
            Err(_) => None,
            Ok((rem, sll)) => {
                match sll.arphrd_type {
                    778 /* ARPHRD_IPGRE */ => Some(PacketData::L4(47, rem)),
                    803 /* ARPHRD_IEEE80211_RADIOTAP */ |
                    824 /* ARPHRD_NETLINK */ => None,
                    _ => Some(PacketData::L3(sll.protocol_type, rem)),
                }
            }
        }
    }
}

struct SLL2Header {
    protocol_type: u16,
    _reserved: u16,
    _interface_index: u32,
    arphrd_type: u16,
    _packet_type: u8,
    _ll_addr_len: u8,
    _ll_addr: u64,
}

fn parse_sll2_header(i: &[u8]) -> IResult<&[u8], SLL2Header> {
    let (i, protocol_type) = be_u16(i)?;
    let (i, _reserved) = be_u16(i)?;
    let (i, _interface_index) = be_u32(i)?;
    let (i, arphrd_type) = be_u16(i)?;
    let (i, _packet_type) = be_u8(i)?;
    let (i, _ll_addr_len) = be_u8(i)?;
    let (i, _ll_addr) = be_u64(i)?;
    let header = SLL2Header {
        protocol_type,
        _reserved,
        _interface_index,
        arphrd_type,
        _packet_type,
        _ll_addr_len,
        _ll_addr,
    };
    Ok((i, header))
}

/// Get packet data for LINKTYPE_IPV4 (228)
///
/// Raw IPv4; the packet begins with an IPv4 header.
pub fn get_packetdata_ipv4(i: &[u8], _caplen: usize) -> Option<PacketData> {
    Some(PacketData::L3(ETHERTYPE_IPV4, i))
}

/// Get packet data for LINKTYPE_IPV6 (229)
///
/// Raw IPv4; the packet begins with an IPv6 header.
pub fn get_packetdata_ipv6(i: &[u8], _caplen: usize) -> Option<PacketData> {
    Some(PacketData::L3(ETHERTYPE_IPV6, i))
}

/// Get packet data, depending on linktype.
///
/// Returns packet data, or None if data could not be extracted (for ex, inner parsing error).
/// If linktype is not supported, `PacketData::Unsupported` is used.
pub fn get_packetdata(i: &[u8], linktype: Linktype, caplen: usize) -> Option<PacketData> {
    match linktype {
        Linktype::NULL => get_packetdata_null(i, caplen),
        Linktype::ETHERNET => get_packetdata_ethernet(i, caplen),
        Linktype::RAW => get_packetdata_raw(i, caplen),
        Linktype::LINUX_SLL => get_packetdata_linux_sll(i, caplen),
        Linktype::LINUX_SLL2 => get_packetdata_linux_sll2(i, caplen),
        Linktype::IPV4 => get_packetdata_ipv4(i, caplen),
        Linktype::IPV6 => get_packetdata_ipv6(i, caplen),
        Linktype::NFLOG => get_packetdata_nflog(i, caplen),
        Linktype::WIRESHARK_UPPER_PDU => get_packetdata_wireshark_upper_pdu(i, caplen),
        _ => Some(PacketData::Unsupported(i)),
    }
}
