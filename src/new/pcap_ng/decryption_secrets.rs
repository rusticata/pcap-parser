use rusticata_macros::{align32, newtype_enum};
use winnow::{
    bytes::take,
    error::{ErrMode, ErrorKind, ParseError},
    stream::{AsBytes, Stream, StreamIsPartial},
    IResult, Parser,
};

use super::blockparser::{ng_block_parser, PcapNGBlockParser};
use super::{opt_parse_options, PcapNGOption, DSB_MAGIC};
use crate::endianness::{PcapBE, PcapEndianness, PcapLE};
use crate::PcapError;

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct SecretsType(pub u32);

newtype_enum! {
    impl debug SecretsType {
        TlsKeyLog = 0x544c_534b, // TLSK
        WireguardKeyLog = 0x5747_4b4c,
    }
}

#[derive(Debug)]
pub struct DecryptionSecretsBlock<I: AsBytes> {
    pub block_type: u32,
    pub block_len1: u32,
    pub secrets_type: SecretsType,
    pub secrets_len: u32,
    pub data: I,
    pub options: Vec<PcapNGOption<I>>,
    pub block_len2: u32,
}

impl<Input, En: PcapEndianness> PcapNGBlockParser<Input, En>
    for DecryptionSecretsBlock<Input::Slice>
where
    Input: Stream<Token = u8, Slice = Input> + StreamIsPartial,
    <Input as Stream>::Slice: AsBytes,
{
    const HDR_SZ: usize = 20;
    const MAGIC: u32 = DSB_MAGIC;

    type Output = DecryptionSecretsBlock<Input::Slice>;

    fn inner_parse<E: ParseError<Input>>(
        block_type: u32,
        block_len1: u32,
        i: Input,
        block_len2: u32,
    ) -> IResult<Input, Self::Output, E> {
        // caller function already tested header type(magic) and length
        // read end of header
        let (i, secrets_type) = En::parse_u32_gen(i)?;
        let (i, secrets_len) = En::parse_u32_gen(i)?;
        // read packet data
        // align32 can overflow
        if secrets_len >= ::std::u32::MAX - 4 {
            return Err(ErrMode::Backtrack(E::from_error_kind(i, ErrorKind::Verify)));
        }
        let padded_length = align32!(secrets_len);
        let (i, data) = take(padded_length)(i)?;
        // read options
        let current_offset = (20 + padded_length) as usize;
        let (i, options) = opt_parse_options::<_, En, E>(i, block_len1 as usize, current_offset)?;
        if block_len2 != block_len1 {
            return Err(ErrMode::Backtrack(E::from_error_kind(i, ErrorKind::Verify)));
        }
        let block = DecryptionSecretsBlock {
            block_type,
            block_len1,
            secrets_type: SecretsType(secrets_type),
            secrets_len,
            data,
            options,
            block_len2,
        };
        Ok((i, block))
    }
}

/// Parse a Decryption Secrets Block (little-endian)
pub fn parse_decryptionsecretsblock_le<I>(
    i: I,
) -> IResult<I, DecryptionSecretsBlock<I>, PcapError<I>>
where
    I: Stream<Token = u8, Slice = I> + StreamIsPartial,
    <I as Stream>::Slice: AsBytes,
{
    ng_block_parser::<I, DecryptionSecretsBlock<_>, PcapLE, _, _>().parse_next(i)
}

/// Parse a Decryption Secrets Block (big-endian)
pub fn parse_decryptionsecretsblock_be<I>(
    i: I,
) -> IResult<I, DecryptionSecretsBlock<I>, PcapError<I>>
where
    I: Stream<Token = u8, Slice = I> + StreamIsPartial,
    <I as Stream>::Slice: AsBytes,
{
    ng_block_parser::<I, DecryptionSecretsBlock<_>, PcapBE, _, _>().parse_next(i)
}
