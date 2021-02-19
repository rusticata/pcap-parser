use hex_literal::hex;
use pcap_parser::pcapng::*;
use pcap_parser::traits::*;
use pcap_parser::*;
use std::fs::File;
use std::io::BufReader;

static TEST001_BE: &[u8] = include_bytes!("../assets/test001-be.pcapng");
static TEST001_LE: &[u8] = include_bytes!("../assets/test001-le.pcapng");
static TEST010_LE: &[u8] = include_bytes!("../assets/test010-le.pcapng");
static TEST016_BE: &[u8] = include_bytes!("../assets/test016-be.pcapng");
static TEST016_LE: &[u8] = include_bytes!("../assets/test016-le.pcapng");

const NG_BLOCK_UNK_BE: &[u8] = &hex!("12 34 56 78 00 00 00 10 12 34 56 78 00 00 00 10");
const NG_BLOCK_UNK_LE: &[u8] = &hex!("12 34 56 78 10 00 00 00 12 34 56 78 10 00 00 00");

#[test]
fn ng_block_shb_be() {
    let input = &TEST016_BE[0..=95];
    let (i, block) = parse_sectionheaderblock_be(input).unwrap();
    assert!(i.is_empty());
    assert_eq!(block.block_type, SHB_MAGIC.swap_bytes());
    assert!(block.big_endian());
    assert_eq!(block.major_version, 1);
    assert_eq!(block.minor_version, 0);
    assert_eq!(block.section_len, -1);
    assert_eq!(block.options.iter().count(), 5);
}

#[test]
fn ng_block_shb_le() {
    let input = &TEST016_LE[0..=95];
    let (i, block) = parse_sectionheaderblock_le(input).unwrap();
    assert!(i.is_empty());
    assert_eq!(block.block_type, SHB_MAGIC);
    assert!(!block.big_endian());
    assert_eq!(block.major_version, 1);
    assert_eq!(block.minor_version, 0);
    assert_eq!(block.section_len, -1);
    assert_eq!(block.options.iter().count(), 5);
}

#[test]
fn ng_block_idb_be() {
    let input = &TEST016_BE[96..=127];
    let (i, block) = parse_interfacedescriptionblock_be(input).unwrap();
    assert!(i.is_empty());
    assert_eq!(block.block_type, IDB_MAGIC.swap_bytes());
    assert_eq!(block.options.iter().count(), 2);
    assert_eq!(block.linktype, Linktype(1));
    assert_eq!(block.snaplen, 0);
    assert_eq!(block.if_tsresol, 6);
    assert_eq!(block.if_tsoffset, 0);
}

#[test]
fn ng_block_idb_le() {
    let input = &TEST016_LE[96..=127];
    let (i, block) = parse_interfacedescriptionblock_le(input).unwrap();
    assert!(i.is_empty());
    assert_eq!(block.block_type, IDB_MAGIC);
    assert_eq!(block.options.iter().count(), 2);
    assert_eq!(block.linktype, Linktype(1));
    assert_eq!(block.snaplen, 0);
    assert_eq!(block.if_tsresol, 6);
    assert_eq!(block.if_tsoffset, 0);
}

#[test]
fn ng_block_spb_be() {
    let input = &TEST016_BE[1020..=1351];
    let (i, block) = parse_simplepacketblock_be(input).unwrap();
    assert!(i.is_empty());
    assert!(block.big_endian());
    assert_eq!(block.block_type, SPB_MAGIC.swap_bytes());
    assert_eq!(block.block_len1, 332);
    assert_eq!(block.data.len(), 316); // with padding
    let packet_data = block.packet_data();
    assert_eq!(packet_data.len(), 314); // without padding
}

#[test]
fn ng_block_spb_le() {
    let input = &TEST016_LE[1020..=1351];
    let (i, block) = parse_simplepacketblock_le(input).unwrap();
    assert!(i.is_empty());
    assert!(!block.big_endian());
    assert_eq!(block.block_type, SPB_MAGIC);
    assert_eq!(block.block_len1, 332);
    assert_eq!(block.data.len(), 316); // with padding
    let packet_data = block.packet_data();
    assert_eq!(packet_data.len(), 314); // without padding
}

#[test]
fn ng_block_epb_be() {
    let input = &TEST001_BE[148..=495];
    let (i, block) = parse_enhancedpacketblock_be(input).unwrap();
    assert!(i.is_empty());
    assert!(block.big_endian());
    assert_eq!(block.block_type, EPB_MAGIC.swap_bytes());
    assert_eq!(block.block_len1, 348);
    assert_eq!(block.data.len(), 316); // with padding
    let packet_data = block.packet_data();
    assert_eq!(packet_data.len(), 314); // without padding
}

#[test]
fn ng_block_epb_le() {
    let input = &TEST001_LE[148..=495];
    let (i, block) = parse_enhancedpacketblock_le(input).unwrap();
    assert!(i.is_empty());
    assert!(!block.big_endian());
    assert_eq!(block.block_type, EPB_MAGIC);
    assert_eq!(block.block_len1, 348);
    assert_eq!(block.data.len(), 316); // with padding
    let packet_data = block.packet_data();
    assert_eq!(packet_data.len(), 314); // without padding
}

#[test]
fn ng_block_nrb_be() {
    let input = &TEST016_BE[128..=223];
    let (i, block) = parse_nameresolutionblock_be(input).unwrap();
    assert!(i.is_empty());
    assert_eq!(block.block_type, NRB_MAGIC.swap_bytes());
    assert_eq!(block.nr.len(), 4);
    assert_eq!(block.options.len(), 2);
    assert_eq!(block.block_len1, 96);
}

#[test]
fn ng_block_nrb_le() {
    let input = &TEST016_LE[128..=223];
    let (i, block) = parse_nameresolutionblock_le(input).unwrap();
    assert!(i.is_empty());
    assert_eq!(block.block_type, NRB_MAGIC);
    assert_eq!(block.nr.len(), 4);
    assert_eq!(block.options.len(), 2);
    assert_eq!(block.block_len1, 96);
}

#[test]
fn ng_block_unknown_be() {
    let (i, block) = parse_unknownblock_be(NG_BLOCK_UNK_BE).unwrap();
    assert!(i.is_empty());
    assert_eq!(block.block_type, 0x78563412);
    assert_eq!(block.block_len1, 16);
}

#[test]
fn ng_block_unknown_le() {
    let (i, block) = parse_unknownblock_le(NG_BLOCK_UNK_LE).unwrap();
    assert!(i.is_empty());
    assert_eq!(block.block_type, 0x78563412);
    assert_eq!(block.block_len1, 16);
}

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
