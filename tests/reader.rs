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
