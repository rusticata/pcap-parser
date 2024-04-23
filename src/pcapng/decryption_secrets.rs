use nom::bytes::streaming::take;
use nom::error::{ErrorKind, ParseError};
use nom::{Err, IResult};
use rusticata_macros::{align32, newtype_enum};

use crate::endianness::{PcapBE, PcapEndianness, PcapLE};
use crate::{opt_parse_options, PcapError, PcapNGOption, DSB_MAGIC};

use super::*;

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct SecretsType(pub u32);

newtype_enum! {
    impl debug SecretsType {
        TlsKeyLog = 0x544c_534b, // TLSK
        WireguardKeyLog = 0x5747_4b4c,
    }
}

#[derive(Debug)]
pub struct DecryptionSecretsBlock<'a> {
    pub block_type: u32,
    pub block_len1: u32,
    pub secrets_type: SecretsType,
    pub secrets_len: u32,
    pub data: &'a [u8],
    pub options: Vec<PcapNGOption<'a>>,
    pub block_len2: u32,
}

impl<'a, En: PcapEndianness> PcapNGBlockParser<'a, En, DecryptionSecretsBlock<'a>>
    for DecryptionSecretsBlock<'a>
{
    const HDR_SZ: usize = 20;
    const MAGIC: u32 = DSB_MAGIC;

    fn inner_parse<E: ParseError<&'a [u8]>>(
        block_type: u32,
        block_len1: u32,
        i: &'a [u8],
        block_len2: u32,
    ) -> IResult<&'a [u8], DecryptionSecretsBlock<'a>, E> {
        // caller function already tested header type(magic) and length
        // read end of header
        let (i, secrets_type) = En::parse_u32(i)?;
        let (i, secrets_len) = En::parse_u32(i)?;
        // read packet data
        // align32 can overflow
        if secrets_len >= u32::MAX - 4 {
            return Err(Err::Error(E::from_error_kind(i, ErrorKind::Verify)));
        }
        let padded_length = align32!(secrets_len);
        let (i, data) = take(padded_length)(i)?;
        // read options
        let current_offset = (20 + padded_length) as usize;
        let (i, options) = opt_parse_options::<En, E>(i, block_len1 as usize, current_offset)?;
        if block_len2 != block_len1 {
            return Err(Err::Error(E::from_error_kind(i, ErrorKind::Verify)));
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

/// Parse a DecryptionSecrets Block (little-endian)
#[inline]
pub fn parse_decryptionsecretsblock_le(
    i: &[u8],
) -> IResult<&[u8], DecryptionSecretsBlock, PcapError<&[u8]>> {
    ng_block_parser::<DecryptionSecretsBlock, PcapLE, _, _>()(i)
}

/// Parse a DecryptionSecrets Block (big-endian)
#[inline]
pub fn parse_decryptionsecretsblock_be(
    i: &[u8],
) -> IResult<&[u8], DecryptionSecretsBlock, PcapError<&[u8]>> {
    ng_block_parser::<DecryptionSecretsBlock, PcapBE, _, _>()(i)
}
