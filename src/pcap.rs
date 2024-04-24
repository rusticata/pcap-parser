//! PCAP file format
//!
//! See <https://wiki.wireshark.org/Development/LibpcapFileFormat> for details.
//!
//! There are 2 main ways of parsing a PCAP file. The first method is to use
//! [`parse_pcap`]. This method requires to load the entire
//! file to memory, and thus may not be good for large files.
//!
//! The [`PcapCapture`] implements the
//! [`Capture`](crate::Capture) trait to provide generic methods. However,
//! this trait also reads the entire file.
//!
//! The second method is to first parse the PCAP header
//! using [`parse_pcap_header`], then
//! loop over [`parse_pcap_frame`] to get the data.
//! This can be used in a streaming parser.

mod capture;
mod frame;
mod header;
mod reader;

pub use capture::*;
pub use frame::*;
pub use header::*;
pub use reader::*;

#[cfg(test)]
pub mod tests {
    use crate::pcap::{parse_pcap_frame, parse_pcap_header};
    use crate::traits::tests::FRAME_PCAP;
    use hex_literal::hex;
    // ntp.pcap header
    pub const PCAP_HDR: &[u8] = &hex!(
        "
D4 C3 B2 A1 02 00 04 00 00 00 00 00 00 00 00 00
00 00 04 00 01 00 00 00"
    );

    // pcap header with nanosecond-precision timestamping
    pub const PCAP_HDR_NSEC: &[u8] = &hex!(
        "
4D 3C B2 A1 02 00 04 00 00 00 00 00 00 00 00 00
00 00 04 00 01 00 00 00"
    );
    #[test]
    fn test_parse_pcap_header() {
        let (rem, hdr) = parse_pcap_header(PCAP_HDR).expect("header parsing failed");
        assert!(rem.is_empty());
        assert_eq!(hdr.magic_number, 0xa1b2_c3d4);
        assert_eq!(hdr.version_major, 2);
        assert_eq!(hdr.version_minor, 4);
        assert_eq!(hdr.snaplen, 262_144);
        assert!(!hdr.is_nanosecond_precision());
    }
    #[test]
    fn test_parse_nanosecond_precision_pcap_header() {
        let (rem, hdr) = parse_pcap_header(PCAP_HDR_NSEC).expect("header parsing failed");
        assert!(rem.is_empty());
        assert_eq!(hdr.magic_number, 0xa1b2_3c4d);
        assert_eq!(hdr.version_major, 2);
        assert_eq!(hdr.version_minor, 4);
        assert_eq!(hdr.snaplen, 262_144);
        assert!(hdr.is_nanosecond_precision());
    }
    #[test]
    fn test_parse_pcap_frame() {
        let (rem, pkt) = parse_pcap_frame(FRAME_PCAP).expect("packet parsing failed");
        assert!(rem.is_empty());
        assert_eq!(pkt.origlen, 74);
        assert_eq!(pkt.ts_usec, 562_913);
        assert_eq!(pkt.ts_sec, 1_515_933_236);
    }
}
