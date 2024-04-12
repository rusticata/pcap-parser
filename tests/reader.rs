use std::{fs::File, io::BufReader};

use pcap_parser::{create_reader, PcapError};

#[test]
fn test_empty_reader_error() {
    let empty: &[u8] = &[];
    let res = create_reader(1024, empty);
    assert!(res.is_err());
    if let Err(err) = res {
        assert_eq!(err, PcapError::Eof);
    } else {
        unreachable!();
    }
}

#[test]
fn test_empty_reader_incomplete() {
    let empty: &[u8] = &[0];
    let res = create_reader(1024, empty);
    assert!(res.is_err());
    if let Err(err) = res {
        assert!(matches!(err, PcapError::Incomplete(_)));
    } else {
        unreachable!();
    }
}

#[test]
fn new_test_pcap_capture_from_file_and_iter_le() {
    use pcap_parser::new::blocks::PcapBlockOwned;
    use pcap_parser::new::pcap::LegacyPcapReader;
    use pcap_parser::new::reader::*;

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
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                reader.refill().unwrap();
            }
            Err(e) => panic!("error while reading: {:?}", e),
        }
    }
    assert_eq!(num_blocks, 13); /* 1 (header) + 12 (data blocks) */
}

#[test]
fn new_test_pcapng_reader() {
    use pcap_parser::new::blocks::PcapBlockOwned;
    use pcap_parser::new::pcap_ng::{Block, PcapNGReader};
    use pcap_parser::new::reader::*;

    let path = "assets/test001-le.pcapng";
    let file = File::open(path).unwrap();
    let buffered = BufReader::new(file);
    let mut num_blocks = 0;
    let mut reader = PcapNGReader::new(65536, buffered).expect("PcapNGReader");
    let expected_origlen = &[0, 0, 314, 342, 314, 342];
    while let Ok((offset, block)) = reader.next() {
        match block {
            // PcapBlockOwned::NG(Block::EnhancedPacket(epb)) => {
            //     assert_eq!(expected_origlen[num_blocks], epb.origlen);
            // }
            PcapBlockOwned::NG(_) => (),
            PcapBlockOwned::LegacyHeader(_) | PcapBlockOwned::Legacy(_) => {
                panic!("unexpected Legacy data")
            }
        }
        num_blocks += 1;
        reader.consume(offset);
    }
    assert_eq!(num_blocks, 6);
}
