extern crate nom;
extern crate pcap_parser;

use hex_literal::hex;
use pcap_parser::pcapng::Block;
use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::*;
use std::fs::File;
use std::io::BufReader;

static TEST001_BE: &[u8] = include_bytes!("../assets/test001-be.pcapng");
static TEST001_LE: &[u8] = include_bytes!("../assets/test001-le.pcapng");
static TEST010_LE: &[u8] = include_bytes!("../assets/test010-le.pcapng");

#[test]
fn test_pcapng_capture_from_file_and_iter_le() {
    let cap =
        PcapNGCapture::from_file(TEST001_LE).expect("could not parse file into PcapNGCapture");
    let expected_origlen = &[0, 0, 314, 342, 314, 342];
    for (block, expected_len) in cap.iter().zip(expected_origlen.iter()) {
        if let PcapBlock::NG(Block::EnhancedPacket(epb)) = block {
            println!("block total length: {}", epb.block_len1);
            println!("captured length: {}", epb.caplen);
            assert_eq!(epb.caplen, *expected_len);
        }
    }
}

#[test]
fn test_pcapng_capture_from_file_and_iter_be() {
    let cap =
        PcapNGCapture::from_file(TEST001_BE).expect("could not parse file into PcapNGCapture");
    for block in cap.iter() {
        if let PcapBlock::NG(Block::EnhancedPacket(epb)) = block {
            println!("block total length: {}", epb.block_len1);
            println!("captured length: {}", epb.caplen);
        }
    }
}

#[test]
fn test_pcapng_iter_section_interfaces() {
    let (_, section) = parse_section(TEST001_LE).expect("could not parse section");
    assert_eq!(section.iter_interfaces().count(), 1);
    for (idx, interface) in section.iter_interfaces().enumerate() {
        println!("found interface {}", idx);
        println!("  linktype: {}", interface.linktype);
        println!("  snaplen: {}", interface.snaplen);
    }
}

#[test]
fn test_pcapng_iter_section_interfaces_be() {
    let (_, section) = parse_section(TEST001_BE).expect("could not parse section");
    assert_eq!(section.iter_interfaces().count(), 1);
    for (idx, interface) in section.iter_interfaces().enumerate() {
        println!("found interface {}", idx);
        println!("  linktype: {}", interface.linktype);
        println!("  snaplen: {}", interface.snaplen);
    }
}

#[test]
fn test_pcapng_simple_packets() {
    let (rem, section) = parse_section(TEST010_LE).expect("could not parse section");
    assert!(rem.is_empty());
    assert_eq!(section.iter_interfaces().count(), 1);
    let expected_origlen = &[0, 0, 314, 342, 314, 342];
    for (block, expected_len) in section.iter().zip(expected_origlen.iter()) {
        if let PcapBlock::NG(Block::SimplePacket(spb)) = block {
            assert_eq!(spb.origlen, *expected_len);
        }
    }
}

#[test]
fn test_pcapng_reader() {
    let path = "assets/test001-le.pcapng";
    let file = File::open(path).unwrap();
    let buffered = BufReader::new(file);
    let mut num_blocks = 0;
    let mut reader = PcapNGReader::new(65536, buffered).expect("PcapNGReader");
    let expected_origlen = &[0, 0, 314, 342, 314, 342];
    while let Ok((offset, block)) = reader.next() {
        match block {
            PcapBlockOwned::NG(Block::EnhancedPacket(epb)) => {
                assert_eq!(expected_origlen[num_blocks], epb.origlen);
            }
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

#[test]
fn test_pcapng_reader_be() {
    let path = "assets/test001-be.pcapng";
    let file = File::open(path).unwrap();
    let buffered = BufReader::new(file);
    let mut num_blocks = 0;
    let mut reader = PcapNGReader::new(65536, buffered).expect("PcapNGReader");
    let expected_origlen = &[0, 0, 314, 342, 314, 342];
    loop {
        match reader.next() {
            Ok((offset, block)) => {
                match block {
                    PcapBlockOwned::NG(Block::EnhancedPacket(epb)) => {
                        assert_eq!(expected_origlen[num_blocks], epb.origlen);
                    }
                    PcapBlockOwned::NG(_) => (),
                    PcapBlockOwned::LegacyHeader(_) | PcapBlockOwned::Legacy(_) => {
                        panic!("unexpected Legacy data")
                    }
                }
                num_blocks += 1;
                reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete) => {
                reader.refill().unwrap();
            }
            Err(e) => panic!("error while reading: {:?}", e),
        }
    }
    assert_eq!(num_blocks, 6);
}

#[test]
fn test_pcapng_decryptionsecretsblock() {
    // block 3 from file dtls12-aes128ccm8-dsb.pcapng (wireshark repo)
    let data = hex!(
        "
0a 00 00 00 c4 00 00 00 4b 53 4c 54 b0 00 00 00
43 4c 49 45 4e 54 5f 52 41 4e 44 4f 4d 20 35 38
38 65 35 66 39 64 63 37 37 38 63 65 66 32 32 34
30 35 66 34 32 66 39 62 65 61 32 35 39 32 38 62
64 30 33 31 32 63 65 31 34 64 36 34 32 64 30 33
34 64 32 34 66 34 66 61 62 36 37 32 66 63 20 37
30 35 37 66 33 64 37 30 36 63 66 30 36 38 30 61
34 30 65 34 66 32 65 30 37 34 37 63 65 37 38 63
65 39 38 64 61 32 36 32 32 65 62 39 61 39 35 34
33 66 37 66 31 35 34 36 33 37 34 34 31 35 37 32
35 36 61 37 39 36 64 62 35 30 62 62 65 36 35 63
64 62 64 63 32 39 32 61 30 39 33 33 35 62 34 0a
c4 00 00 00"
    );
    let (rem, block) = parse_block(&data).expect("could not parse DSB");
    assert!(rem.is_empty());
    if let Block::DecryptionSecrets(dsb) = block {
        assert_eq!(dsb.secrets_type, SecretsType::TlsKeyLog);
        assert!(std::str::from_utf8(dsb.data).is_ok());
    } else {
        unreachable!();
    }
}
