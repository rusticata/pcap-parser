use nom::error::{ErrorKind, ParseError};
use std::fmt;

#[derive(Debug, PartialEq)]
pub enum PcapError<I: Sized> {
    Eof,
    ReadError,
    Incomplete,

    HeaderNotRecognized,

    NomError(I, ErrorKind),
    OwnedNomError(Vec<u8>, ErrorKind),
}

impl<I> PcapError<I>
where
    I: AsRef<[u8]> + Sized,
{
    pub fn to_owned_vec(&self) -> PcapError<&'static [u8]> {
        match self {
            PcapError::Eof => PcapError::Eof,
            PcapError::ReadError => PcapError::ReadError,
            PcapError::Incomplete => PcapError::Incomplete,
            PcapError::HeaderNotRecognized => PcapError::HeaderNotRecognized,
            PcapError::NomError(i, errorkind) => {
                PcapError::OwnedNomError(i.as_ref().to_vec(), *errorkind)
            }
            PcapError::OwnedNomError(v, e) => PcapError::OwnedNomError(v.clone(), *e),
        }
    }

    pub fn from_data(input: I, errorkind: ErrorKind) -> Self {
        Self::NomError(input, errorkind)
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
    I: std::fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PcapError::Eof => write!(f, "End of file"),
            PcapError::ReadError => write!(f, "Read error"),
            PcapError::Incomplete => write!(f, "Incomplete read"),
            PcapError::HeaderNotRecognized => write!(f, "Header not recognized as PCAP or PCAPNG"),
            PcapError::NomError(i, e) => write!(f, "Internal parser error {:?}, input {:?}", e, i),
            PcapError::OwnedNomError(i, e) => {
                write!(f, "Internal parser error {:?}, input {:?}", e, &i)
            }
        }
    }
}

impl<I> std::error::Error for PcapError<I> where I: std::fmt::Debug {}
