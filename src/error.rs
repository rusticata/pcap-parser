use nom::error::{ErrorKind, ParseError};
use std::fmt;

/// The error type which is returned when reading a pcap file
#[derive(Debug, PartialEq)]
pub enum PcapError<I: Sized> {
    /// No more data available
    Eof,
    /// Buffer capacity is too small, and some full frame cannot be stored
    BufferTooSmall,
    /// Expected more data but got EOF
    UnexpectedEof,
    /// An error happened during a `read` operation
    ReadError,
    /// Last block is incomplete, and no more data available
    Incomplete(usize),

    /// File could not be recognized as Pcap nor Pcap-NG
    HeaderNotRecognized,

    /// An error encountered during parsing
    NomError(I, ErrorKind),
    /// An error encountered during parsing (owned version)
    OwnedNomError(Vec<u8>, ErrorKind),
}

impl<I> PcapError<I> {
    /// Creates a `PcapError` from input and error kind.
    pub fn from_data(input: I, errorkind: ErrorKind) -> Self {
        Self::NomError(input, errorkind)
    }
}

impl<I> PcapError<I>
where
    I: AsRef<[u8]> + Sized,
{
    /// Creates an owned `PcapError` object from borrowed data, cloning object.
    /// Owned object has `'static` lifetime.
    pub fn to_owned_vec(&self) -> PcapError<&'static [u8]> {
        match self {
            PcapError::Eof => PcapError::Eof,
            PcapError::BufferTooSmall => PcapError::BufferTooSmall,
            PcapError::UnexpectedEof => PcapError::UnexpectedEof,
            PcapError::ReadError => PcapError::ReadError,
            PcapError::Incomplete(n) => PcapError::Incomplete(*n),
            PcapError::HeaderNotRecognized => PcapError::HeaderNotRecognized,
            PcapError::NomError(i, errorkind) => {
                PcapError::OwnedNomError(i.as_ref().to_vec(), *errorkind)
            }
            PcapError::OwnedNomError(v, e) => PcapError::OwnedNomError(v.clone(), *e),
        }
    }
}

impl<I> ParseError<I> for PcapError<I> {
    fn from_error_kind(input: I, kind: ErrorKind) -> Self {
        PcapError::NomError(input, kind)
    }
    fn append(input: I, kind: ErrorKind, _other: Self) -> Self {
        PcapError::NomError(input, kind)
    }
}

impl<I> fmt::Display for PcapError<I>
where
    I: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PcapError::Eof => write!(f, "End of file"),
            PcapError::BufferTooSmall => write!(f, "Buffer is too small"),
            PcapError::UnexpectedEof => write!(f, "Unexpected end of file"),
            PcapError::ReadError => write!(f, "Read error"),
            PcapError::Incomplete(n) => write!(f, "Incomplete read: {}", n),
            PcapError::HeaderNotRecognized => write!(f, "Header not recognized as PCAP or PCAPNG"),
            PcapError::NomError(i, e) => write!(f, "Internal parser error {:?}, input {:?}", e, i),
            PcapError::OwnedNomError(i, e) => {
                write!(f, "Internal parser error {:?}, input {:?}", e, &i)
            }
        }
    }
}

impl<I> std::error::Error for PcapError<I> where I: fmt::Debug {}
