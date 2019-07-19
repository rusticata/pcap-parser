use crate::Packet;

pub use crate::pcap_nflog::*;

pub fn get_data_raw<'a>(packet: &'a Packet) -> &'a [u8] {
    // debug!("data.len: {}, caplen: {}", packet.data.len(), packet.header.caplen);
    let maxlen = packet.header.caplen as usize;
    &packet.data[..maxlen]
}

// BSD loopback encapsulation; the link layer header is a 4-byte field, in host byte order,
// containing a value of 2 for IPv4 packets, a value of either 24, 28, or 30 for IPv6 packets, a
// value of 7 for OSI packets, or a value of 23 for IPX packets. All of the IPv6 values correspond
// to IPv6 packets; code reading files should check for all of them.
// Note that ``host byte order'' is the byte order of the machine on which the packets are
// captured; if a live capture is being done, ``host byte order'' is the byte order of the machine
// capturing the packets, but if a ``savefile'' is being read, the byte order is not necessarily
// that of the machine reading the capture file.
pub fn get_data_null<'a>(packet: &'a Packet) -> &'a [u8] {
    // debug!("data.len: {}, caplen: {}", packet.data.len(), packet.header.caplen);
    let maxlen = packet.header.caplen as usize;
    &packet.data[4..maxlen]
}

pub fn get_data_ethernet<'a>(packet: &'a Packet) -> &'a [u8] {
    // debug!("data.len: {}, caplen: {}", packet.data.len(), packet.header.caplen);
    let maxlen = packet.header.caplen as usize;
    &packet.data[14..maxlen]
}

/// See http://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html
pub fn get_data_linux_cooked<'a>(packet: &'a Packet) -> &'a [u8] {
    // debug!("data.len: {}, caplen: {}", packet.data.len(), packet.header.caplen);
    let maxlen = packet.header.caplen as usize;
    &packet.data[16..maxlen]
}
