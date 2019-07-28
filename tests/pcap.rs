extern crate nom;
extern crate pcap_parser;

use nom::ErrorKind;
use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::*;
use std::fs::File;
use std::io::BufReader;

static TEST_NTP: &'static [u8] = include_bytes!("../assets/ntp.pcap");

#[test]
fn test_pcap_capture_from_file_and_iter_le() {
    let cap = PcapCapture::from_file(TEST_NTP).expect("could not parse file into PcapNGCapture");
    for block in cap.iter() {
        match block {
            PcapBlock::LegacyHeader(_) => (),
            PcapBlock::Legacy(b) => {
                assert_eq!(b.caplen, 90);
            }
            PcapBlock::NG(_) => panic!("unexpected NG data"),
        }
    }
}

#[test]
fn test_pcap_reader() {
    let path = "assets/ntp.pcap";
    let file = File::open(path).unwrap();
    let buffered = BufReader::new(file);
    let mut num_blocks = 0;
    let mut reader = LegacyPcapReader::new(65536, buffered).expect("LegacyPcapReader");
    loop {
        match reader.next() {
            Ok((offset, block)) => {
                num_blocks += 1;
                match block {
                    PcapBlockOwned::LegacyHeader(_) => (),
                    PcapBlockOwned::Legacy(b) => {
                        assert_eq!(b.caplen, 90);
                    }
                    PcapBlockOwned::NG(_) => panic!("unexpected NG data"),
                }
                reader.consume(offset);
            }
            Err(ErrorKind::Eof) => break,
            Err(e) => panic!("error while reading: {:?}", e),
        }
    }
    assert_eq!(num_blocks, 13); /* 1 (header) + 12 (data blocks) */
}
