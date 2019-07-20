extern crate pcap_parser;

use pcap_parser::pcapng::Block;
use pcap_parser::traits::PcapNGBlock;
use pcap_parser::*;

static TEST_NTP: &'static [u8] = include_bytes!("../assets/ntp.pcap");

#[test]
fn test_pcap_capture_from_file_and_iter_le() {
    let cap = PcapCapture::from_file(TEST_NTP).expect("could not parse file into PcapNGCapture");
    let expected_origlen = &[0, 0, 314, 342, 314, 342];
    for (block, expected_len) in cap.iter().zip(expected_origlen.iter()) {
        match block {
            PcapBlock::NG(Block::EnhancedPacket(epb)) => {
                println!("block total length: {}", epb.block_length());
                println!("captured length: {}", epb.caplen);
                assert_eq!(epb.caplen, *expected_len);
            }
            _ => (),
        }
    }
}
