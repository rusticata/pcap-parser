extern crate nom;
extern crate pcap_parser;

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
