use nom::error::{ErrorKind, ParseError};
use std::error::Error;
use std::fmt;

#[derive(Debug, PartialEq)]
pub enum PcapError {
    Eof,
    ReadError,
    Incomplete,

    HeaderNotRecognized,

    NomError(ErrorKind),
}

impl<I> ParseError<I> for PcapError {
    fn from_error_kind(_input: I, kind: ErrorKind) -> Self {
        PcapError::NomError(kind)
    }
    fn append(_input: I, kind: ErrorKind, _other: Self) -> Self {
        PcapError::NomError(kind)
    }
}

impl fmt::Display for PcapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PcapError::Eof => write!(f, "End of file"),
            PcapError::ReadError => write!(f, "Read error"),
            PcapError::Incomplete => write!(f, "Incomplete read"),
            PcapError::HeaderNotRecognized => write!(f, "Header not recognized as PCAP or PCAPNG"),
            PcapError::NomError(e) => write!(f, "Internal parser error {:?}", e),
        }
    }
}

impl Error for PcapError {}
