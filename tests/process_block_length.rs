use nom::error::ErrorKind;
use pcap_parser::pcapng::{
    parse_block_be, parse_block_le, parse_processinformationblock_be,
    parse_processinformationblock_le, Block,
};
use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::{PcapBlockOwned, PcapError, PcapNGReader, PIB_MAGIC};

fn word(value: u32, big_endian: bool) -> [u8; 4] {
    if big_endian {
        value.to_be_bytes()
    } else {
        value.to_le_bytes()
    }
}

fn process_block(length: u32, big_endian: bool) -> Vec<u8> {
    [PIB_MAGIC, length, 42, length]
        .iter()
        .flat_map(|value| word(*value, big_endian))
        .collect()
}

fn capture(block: &[u8], big_endian: bool) -> Vec<u8> {
    let version = if big_endian { 0x0001_0000 } else { 1 };
    let mut bytes: Vec<u8> = [
        0x0a0d_0d0a,
        28,
        0x1a2b_3c4d,
        version,
        u32::MAX,
        u32::MAX,
        28,
    ]
    .iter()
    .flat_map(|value| word(*value, big_endian))
    .collect();
    bytes.extend_from_slice(block);
    bytes
}

#[test]
fn process_block_rejects_short_lengths() {
    for big_endian in [false, true] {
        let parse = if big_endian {
            parse_block_be
        } else {
            parse_block_le
        };
        let parse_process = if big_endian {
            parse_processinformationblock_be
        } else {
            parse_processinformationblock_le
        };
        for length in 0..16 {
            let block = process_block(length, big_endian);
            assert!(
                matches!(
                    parse(&block),
                    Err(nom::Err::Error(PcapError::NomError(_, ErrorKind::Verify)))
                ),
                "length {}, big_endian {}",
                length,
                big_endian
            );
            assert!(
                matches!(
                    parse_process(&block),
                    Err(nom::Err::Error(PcapError::NomError(_, ErrorKind::Verify)))
                ),
                "length {}, big_endian {}",
                length,
                big_endian
            );
        }
    }
}

#[test]
fn process_block_reader_rejects_short_lengths() {
    for big_endian in [false, true] {
        for length in 0..16 {
            let bytes = capture(&process_block(length, big_endian), big_endian);
            let mut reader = PcapNGReader::new(128, bytes.as_slice()).unwrap();
            let (offset, block) = reader.next().unwrap();
            assert!(matches!(block, PcapBlockOwned::NG(Block::SectionHeader(_))));
            reader.consume(offset);
            assert!(
                matches!(
                    reader.next(),
                    Err(PcapError::NomError(_, ErrorKind::Verify))
                ),
                "length {}, big_endian {}",
                length,
                big_endian
            );
        }
    }
}

#[test]
fn process_block_preserves_valid_and_incomplete_input() {
    for big_endian in [false, true] {
        let parse = if big_endian {
            parse_block_be
        } else {
            parse_block_le
        };
        let block = process_block(16, big_endian);
        for length in 0..block.len() {
            assert!(matches!(
                parse(&block[..length]),
                Err(nom::Err::Incomplete(_))
            ));
        }
        let mut two_blocks = block.clone();
        two_blocks.extend_from_slice(&block);
        let (remaining, parsed) = parse(&two_blocks).unwrap();
        assert_eq!(remaining, block);
        match parsed {
            Block::ProcessInformation(process) => {
                assert_eq!(process.process_id, 42);
                assert!(process.options.is_empty());
                assert_eq!(process.block_len1, 16);
                assert_eq!(process.block_len2, 16);
            }
            _ => panic!("expected process information"),
        }
        let bytes = capture(&two_blocks, big_endian);
        let mut reader = PcapNGReader::new(128, bytes.as_slice()).unwrap();
        for expected_offset in [28, 16, 16] {
            let (offset, _) = reader.next().unwrap();
            assert_eq!(offset, expected_offset);
            reader.consume(offset);
        }
        reader.refill().unwrap();
        assert!(matches!(reader.next(), Err(PcapError::Eof)));
    }
}

#[test]
fn process_block_truncated_malformed_input_keeps_incomplete_semantics() {
    for big_endian in [false, true] {
        let parse = if big_endian {
            parse_block_be
        } else {
            parse_block_le
        };
        // The issue's short block has only twelve physical bytes, with an
        // advertised length of eight. Preserve the normal short-input result.
        let block = process_block(8, big_endian);
        let truncated = &block[..12];
        assert!(matches!(parse(truncated), Err(nom::Err::Incomplete(_))));
        let bytes = capture(truncated, big_endian);
        let mut reader = PcapNGReader::new(128, bytes.as_slice()).unwrap();
        let (offset, _) = reader.next().unwrap();
        reader.consume(offset);
        assert!(matches!(reader.next(), Err(PcapError::Incomplete(_))));
        reader.refill().unwrap();
        assert!(matches!(reader.next(), Err(PcapError::UnexpectedEof)));
    }
}
