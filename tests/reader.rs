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

// Streaming decoders can reject empty output buffers. No input should be
// requested once the complete header is already available.
struct NoEmptyReads<'a>(&'a [u8]);

impl std::io::Read for NoEmptyReads<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "output buffer is full",
            ));
        }
        std::io::Read::read(&mut self.0, buf)
    }
}

#[test]
fn create_legacy_reader_with_full_buffer() {
    let input = &include_bytes!("../assets/ntp.pcap")[..];
    let mut reader = create_reader(128, NoEmptyReads(input)).unwrap();
    assert!(reader.next().is_ok());
}

#[test]
fn create_ng_reader_with_full_buffer() {
    let input = &include_bytes!("../assets/test001-le.pcapng")[..];
    let mut reader = create_reader(128, NoEmptyReads(input)).unwrap();
    assert!(reader.next().is_ok());
}

// Reading from this source would block while the producer waits for the caller
// to process the buffered header.
struct NoReads;

impl std::io::Read for NoReads {
    fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
        panic!("complete buffered header must not require more input");
    }
}

#[test]
fn legacy_from_buffer_uses_complete_header_without_reading() {
    for capacity in [24, 128] {
        let mut buffer = circular::Buffer::with_capacity(capacity);
        buffer.space()[..24].copy_from_slice(&include_bytes!("../assets/ntp.pcap")[..24]);
        buffer.fill(24);
        assert!(pcap_parser::LegacyPcapReader::from_buffer(buffer, NoReads).is_ok());
    }
}

#[test]
fn ng_from_buffer_uses_complete_header_without_reading() {
    let header =
        &hex_literal::hex!("0a0d0d0a 1c000000 4d3c2b1a 01000000 ffffffffffffffff 1c000000");
    for capacity in [header.len(), 128] {
        let mut buffer = circular::Buffer::with_capacity(capacity);
        buffer.space()[..header.len()].copy_from_slice(header);
        buffer.fill(header.len());
        assert!(pcap_parser::PcapNGReader::from_buffer(buffer, NoReads).is_ok());
    }
}

struct CountReads<'a> {
    input: &'a [u8],
    calls: &'a std::cell::Cell<usize>,
}

impl std::io::Read for CountReads<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.calls.set(self.calls.get() + 1);
        std::io::Read::read(&mut self.input, buf)
    }
}

#[test]
fn ng_from_buffer_preserves_variable_headers_and_refills() {
    use pcap_parser::traits::PcapReaderIterator;
    use pcap_parser::{Block, PcapBlockOwned};

    let le = hex_literal::hex!(
        "0a0d0d0a 28000000 4d3c2b1a 01000000 ffffffffffffffff
         02000400 74657374 00000000 28000000"
    );
    let be = hex_literal::hex!(
        "0a0d0d0a 00000028 1a2b3c4d 00010000 ffffffffffffffff
         00020004 74657374 00000000 00000028"
    );
    for header in [&le[..], &be[..]] {
        for split in [0, 3, header.len() - 1, header.len()] {
            let mut buffer = circular::Buffer::with_capacity(header.len());
            buffer.space()[..split].copy_from_slice(&header[..split]);
            buffer.fill(split);
            let calls = std::cell::Cell::new(0);
            let input = CountReads {
                input: &header[split..],
                calls: &calls,
            };
            let mut reader = pcap_parser::PcapNGReader::from_buffer(buffer, input).unwrap();
            assert_eq!(calls.get(), usize::from(split != header.len()));
            let (offset, block) = reader.next().unwrap();
            assert_eq!(offset, header.len());
            match block {
                PcapBlockOwned::NG(Block::SectionHeader(shb)) => {
                    assert_eq!(shb.shb_hardware(), Some(Ok("test")));
                }
                _ => panic!("expected section header"),
            }
        }
    }
}

#[test]
fn legacy_from_buffer_preserves_partial_header_refill() {
    use pcap_parser::traits::PcapReaderIterator;

    let header = &include_bytes!("../assets/ntp.pcap")[..24];
    for split in [0, 3, 23, 24] {
        let mut buffer = circular::Buffer::with_capacity(24);
        buffer.space()[..split].copy_from_slice(&header[..split]);
        buffer.fill(split);
        let calls = std::cell::Cell::new(0);
        let input = CountReads {
            input: &header[split..],
            calls: &calls,
        };
        let mut reader = pcap_parser::LegacyPcapReader::from_buffer(buffer, input).unwrap();
        assert_eq!(calls.get(), usize::from(split != header.len()));
        assert_eq!(reader.next().unwrap().0, header.len());
    }
}
