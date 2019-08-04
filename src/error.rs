use nom::error::{ErrorKind, ParseError};

#[derive(Debug)]
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
