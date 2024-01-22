use hex_literal::hex;
use pcap_parser::pcapng::*;
use pcap_parser::traits::*;
use pcap_parser::*;
use std::fs::File;
use std::io::BufReader;
use std::io::Read;

static TEST001_BE: &[u8] = include_bytes!("../assets/test001-be.pcapng");
static TEST001_LE: &[u8] = include_bytes!("../assets/test001-le.pcapng");
static TEST010_LE: &[u8] = include_bytes!("../assets/test010-le.pcapng");
static TEST016_BE: &[u8] = include_bytes!("../assets/test016-be.pcapng");
static TEST016_LE: &[u8] = include_bytes!("../assets/test016-le.pcapng");
static TEST017_BE: &[u8] = include_bytes!("../assets/test017-be.pcapng");
static TEST017_LE: &[u8] = include_bytes!("../assets/test017-le.pcapng");

const NG_BLOCK_ISB_BE: &[u8] = &hex!(
    "
00 00 00 05 00 00 00 40 00 00 00 01 00 04 C3 97
64 CA 47 AA 00 02 00 08 00 04 C3 97 64 CA 47 AA
00 03 00 08 00 04 C3 97 64 CA 4B 92 00 05 00 08
00 00 00 00 00 00 00 0A 00 00 00 00 00 00 00 40
"
);
const NG_BLOCK_ISB_LE: &[u8] = &hex!(
    "
05 00 00 00 40 00 00 00 01 00 00 00 97 C3 04 00
AA 47 CA 64 02 00 08 00 97 C3 04 00 AA 47 CA 64
03 00 08 00 97 C3 04 00 92 4B CA 64 05 00 08 00
0A 00 00 00 00 00 00 00 00 00 00 00 40 00 00 00
"
);
// block 3 from file dtls12-aes128ccm8-dsb.pcapng (wireshark repo)
pub const NG_BLOCK_DSB_LE: &[u8] = &hex!(
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
    assert_eq!(block.options.len(), 5);
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
    assert_eq!(block.options.len(), 5);
}

#[test]
fn ng_block_idb_be() {
    let input = &TEST016_BE[96..=127];
    let (i, block) = parse_interfacedescriptionblock_be(input).unwrap();
    assert!(i.is_empty());
    assert_eq!(block.block_type, IDB_MAGIC.swap_bytes());
    assert_eq!(block.options.len(), 2);
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
    assert_eq!(block.options.len(), 2);
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
fn ng_block_isb_be() {
    let input = NG_BLOCK_ISB_BE;
    let (i, block) = parse_interfacestatisticsblock_be(input).unwrap();
    assert!(i.is_empty());
    assert_eq!(block.block_type, ISB_MAGIC.swap_bytes());
    assert_eq!(block.if_id, 1);
    assert_eq!(block.options.len(), 4);
    assert_eq!(block.block_len1, 64);
}

#[test]
fn ng_block_isb_le() {
    let input = NG_BLOCK_ISB_LE;
    let (i, block) = parse_interfacestatisticsblock_le(input).unwrap();
    assert!(i.is_empty());
    assert_eq!(block.block_type, ISB_MAGIC);
    assert_eq!(block.if_id, 1);
    assert_eq!(block.options.len(), 4);
    assert_eq!(block.block_len1, 64);
}

#[test]
fn ng_block_dsb_le() {
    let input = NG_BLOCK_DSB_LE;
    let (i, block) = parse_decryptionsecretsblock_le(input).unwrap();
    assert!(i.is_empty());
    assert_eq!(block.block_type, DSB_MAGIC);
    assert_eq!(block.secrets_type, SecretsType::TlsKeyLog);
    assert_eq!(block.secrets_len, 176);
    assert_eq!(block.data.len(), 176);
    assert_eq!(block.options.len(), 0);
    assert_eq!(block.block_len1, 196);
}

#[test]
fn ng_block_cb_be() {
    let input = &TEST017_BE[96..=135];
    let (i, block) = parse_customblock_be(input).unwrap();
    assert!(i.is_empty());
    assert_eq!(block.block_type, CB_MAGIC.swap_bytes());
    assert_eq!(block.pen, 0x7ed9);
    assert_eq!(block.data.len(), 24);
    let s = std::str::from_utf8(block.data).unwrap();
    assert_eq!(s, "an example Custom Block\x00");
    assert_eq!(block.block_len1, 40);
}

#[test]
fn ng_block_cb_le() {
    let input = &TEST017_LE[96..=135];
    let (i, block) = parse_customblock_le(input).unwrap();
    assert!(i.is_empty());
    assert_eq!(block.block_type, CB_MAGIC);
    assert_eq!(block.pen, 0x7ed9);
    assert_eq!(block.data.len(), 24);
    let s = std::str::from_utf8(block.data).unwrap();
    assert_eq!(s, "an example Custom Block\x00");
    assert_eq!(block.block_len1, 40);
}

#[test]
fn ng_block_dcb_be() {
    let input = &TEST017_BE[136..=211];
    let (i, block) = parse_dcb_be(input).unwrap();
    assert!(i.is_empty());
    assert_eq!(block.block_type, DCB_MAGIC.swap_bytes());
    assert_eq!(block.pen, 0x7ed9);
    assert_eq!(block.data.len(), 60);
    let s = std::str::from_utf8(block.data).unwrap();
    assert_eq!(s, "an example Custom Block not to be copied\u{0}\u{1}\u{0}\u{b}test017 DCB\u{0}\u{0}\u{0}\u{0}\u{0}");
    assert_eq!(block.block_len1, 76);
}

#[test]
fn ng_block_dcb_le() {
    let input = &TEST017_LE[136..=211];
    let (i, block) = parse_dcb_le(input).unwrap();
    assert!(i.is_empty());
    assert_eq!(block.block_type, DCB_MAGIC);
    assert_eq!(block.pen, 0x7ed9);
    assert_eq!(block.data.len(), 60);
    let s = std::str::from_utf8(block.data).unwrap();
    assert_eq!(s, "an example Custom Block not to be copied\u{1}\u{0}\u{b}\u{0}test017 DCB\u{0}\u{0}\u{0}\u{0}\u{0}");
    assert_eq!(block.block_len1, 76);
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
            assert_eq!(epb.caplen, *expected_len);
        }
    }
    assert_eq!(cap.iter().count(), 6);
}

#[test]
fn test_pcapng_capture_from_file_and_iter_be() {
    let cap =
        PcapNGCapture::from_file(TEST001_BE).expect("could not parse file into PcapNGCapture");
    let expected_origlen = &[0, 0, 314, 342, 314, 342];
    for (block, expected_len) in cap.iter().zip(expected_origlen.iter()) {
        if let PcapBlock::NG(Block::EnhancedPacket(epb)) = block {
            assert_eq!(epb.caplen, *expected_len);
        }
    }
    assert_eq!(cap.iter().count(), 6);
}

#[test]
fn test_pcapng_iter_section_interfaces() {
    let (_, section) = parse_section(TEST001_LE).expect("could not parse section");
    assert_eq!(section.iter_interfaces().count(), 1);
    let interfaces: Vec<_> = section.iter_interfaces().collect();
    assert_eq!(interfaces.len(), 1);
    let if0 = &interfaces[0];
    assert_eq!(if0.linktype, Linktype(1));
    assert_eq!(if0.snaplen, 0);
}

#[test]
fn test_pcapng_iter_section_interfaces_be() {
    let (_, section) = parse_section(TEST001_BE).expect("could not parse section");
    assert_eq!(section.iter_interfaces().count(), 1);
    let interfaces: Vec<_> = section.iter_interfaces().collect();
    assert_eq!(interfaces.len(), 1);
    let if0 = &interfaces[0];
    assert_eq!(if0.linktype, Linktype(1));
    assert_eq!(if0.snaplen, 0);
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
            Err(PcapError::Incomplete(_)) => {
                reader.refill().unwrap();
            }
            Err(e) => panic!("error while reading: {:?}", e),
        }
    }
    assert_eq!(num_blocks, 6);
}

// related issue: https://github.com/rusticata/pcap-parser/issues/13
#[test]
fn err_eof() {
    let data = include_bytes!("../assets/err-eof.bin");
    let res = parse_block_le(data).expect_err("expected incomplete");
    assert!(res.is_incomplete());
}

// related issue: https://github.com/rusticata/pcap-parser/issues/29
#[test]
fn test_reader_buffer_too_small() {
    let file = File::open("assets/err-buffertoosmall.pcapng").unwrap();
    let mut reader = create_reader(1024, file).expect("PcapNGReader");
    let mut num_blocks = 0;
    let mut num_refills = 0;
    const MAX_REFILLS: usize = 20;
    // the only expected way to exit this loop is to encounter BufferTooSmall
    // check number of refills to detect infinite loops
    loop {
        match reader.next() {
            Ok((offset, _block)) => {
                num_blocks += 1;
                reader.consume(offset)
            }
            Err(PcapError::Incomplete(_)) => {
                num_refills += 1;
                assert!(num_refills < MAX_REFILLS);
                reader.refill().unwrap();
            }
            Err(PcapError::BufferTooSmall) => break,
            Err(e) => panic!("Unexpected error {:?}", e),
        }
    }
    assert_eq!(num_blocks, 9);
}

// related issue: https://github.com/rusticata/pcap-parser/issues/30
#[test]
fn test_pcapng_earlyeofandnotexhausted() {
    let path = "assets/test001-le.pcapng";
    let file = File::open(path).unwrap();
    let buffered = BufReader::new(file);

    // 96 is exactly the size of the first SHB, so the first consume will empty the buffer
    let mut reader = PcapNGReader::new(96, buffered).expect("PcapNGReader");
    let (offset, _block) = reader.next().expect("could not read first block");
    reader.consume(offset);
    // the second read happens in the following situation: buf.available_data == 0 AND buf.position == 0
    assert_eq!(reader.position(), 0);
    assert!(reader.data().is_empty());
    let res = reader.next();
    // res should not be Eof
    assert!(!matches!(res, Err(PcapError::Eof)));
    // res should be Incomplete(4) (attempt to read magic)
    assert!(matches!(res, Err(PcapError::Incomplete(4))));
}

#[test]
fn test_pcapng_reader_eof() {
    let path = "assets/test001-le.pcapng";
    let mut file = File::open(path).unwrap();
    let mut buf = vec![0; 96];
    file.read_exact(&mut buf).unwrap();

    // 96 is exactly the size of the first SHB, so the first consume will empty the buffer
    let mut reader = PcapNGReader::new(250, buf.as_slice()).expect("PcapNGReader");
    let (offset, _block) = reader.next().expect("could not read first block");
    reader.consume(offset);

    // first read should return Incomplete, buf does not know if underlying reader has reached Eof
    let res = reader.next();
    assert!(matches!(res, Err(PcapError::Incomplete(_))));

    reader.refill().unwrap();

    match reader.next() {
        Err(PcapError::Eof) => (),
        Err(e) => panic!("unexpected error {:?}", e),
        Ok(_) => unreachable!(),
    }
}
