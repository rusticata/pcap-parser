use rusticata_macros::newtype_enum;

/// Data link type
///
/// The link-layer header type specifies the type of headers at the beginning
/// of the packet.
///
/// See <http://www.tcpdump.org/linktypes.html>
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Linktype(pub i32);

newtype_enum! {
impl display Linktype {
    NULL = 0,
    ETHERNET = 1,

    FDDI = 10,

    RAW = 101,

    LOOP = 108,
    LINUX_SLL = 113,
    LINUX_SLL2 = 276,

    // Raw IPv4; the packet begins with an IPv4 header.
    IPV4 = 228,
    // Raw IPv6; the packet begins with an IPv6 header.
    IPV6 = 229,

    // Linux netlink NETLINK NFLOG socket log messages.
    // Use the [`pcap_nflog`] module to access content.
    NFLOG = 239,

    //  Upper-layer protocol saves from Wireshark
    WIRESHARK_UPPER_PDU = 252,
}
}
