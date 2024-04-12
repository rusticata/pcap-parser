use rusticata_macros::align32;
use winnow::{
    bytes::take,
    error::{ErrMode, ErrorKind, ParseError},
    stream::{AsBytes, Stream, StreamIsPartial},
    IResult, Parser,
};

use super::blockparser::{ng_block_parser, PcapNGBlockParser};
use super::{build_ts, build_ts_f64, opt_parse_options, PcapNGOption, EPB_MAGIC};
use crate::endianness::{PcapBE, PcapEndianness, PcapLE};
use crate::PcapError;

/// An Enhanced Packet Block (EPB) is the standard container for storing
/// the packets coming from the network.
///
/// This struct is a thin abstraction layer, and stores the raw block data.
/// For ex the `data` field is stored with the padding.
/// It implements the `PcapNGPacketBlock` trait, which provides helper functions.
///
/// ## Examples
///
/// ```rust
/// use pcap_parser::pcapng::parse_enhancedpacketblock_le;
/// use pcap_parser::traits::PcapNGPacketBlock;
///
/// # let input_data = include_bytes!("../assets/test001-le.pcapng");
/// # let pcap_data = &input_data[148..=495];
/// let (i, epb) = parse_enhancedpacketblock_le(pcap_data).unwrap();
/// let packet_data = epb.packet_data();
/// if packet_data.len() < epb.orig_len() as usize {
///     // packet was truncated
/// } else {
///     // we have a full packet
/// }
/// ```
#[derive(Debug)]
pub struct EnhancedPacketBlock<I: AsBytes> {
    // Block type, read as little-endian.
    // If block value is the reverse the the expected magic, this means block is encoded as big-endian
    pub block_type: u32,
    pub block_len1: u32,
    pub if_id: u32,
    pub ts_high: u32,
    pub ts_low: u32,
    /// Captured packet length
    pub caplen: u32,
    /// Original packet length
    pub origlen: u32,
    /// Raw data from packet (with padding)
    pub data: I,
    pub options: Vec<PcapNGOption<I>>,
    pub block_len2: u32,
}

impl<I: AsBytes> EnhancedPacketBlock<I> {
    /// Decode the packet timestamp
    ///
    /// To decode the timestamp, the raw values if_tsresol and if_tsoffset are required.
    /// These values are stored as options in the [`InterfaceDescriptionBlock`]
    /// matching the interface ID.
    ///
    /// Return the timestamp seconds and fractional part (in resolution units)
    #[inline]
    pub fn decode_ts(&self, ts_offset: u64, resolution: u64) -> (u32, u32) {
        build_ts(self.ts_high, self.ts_low, ts_offset, resolution)
    }

    /// Decode the packet timestamp as `f64`
    ///
    /// To decode the timestamp, the resolution and offset are required.
    /// These values are stored as options in the [`InterfaceDescriptionBlock`]
    /// matching the interface ID.
    #[inline]
    pub fn decode_ts_f64(&self, ts_offset: u64, resolution: u64) -> f64 {
        build_ts_f64(self.ts_high, self.ts_low, ts_offset, resolution)
    }
}

// FIXME: implement PcapNGPacketBlock  ?!

impl<Input, En: PcapEndianness> PcapNGBlockParser<Input, En> for EnhancedPacketBlock<Input::Slice>
where
    Input: Stream<Token = u8, Slice = Input> + StreamIsPartial,
    <Input as Stream>::Slice: AsBytes,
{
    const HDR_SZ: usize = 32;
    const MAGIC: u32 = EPB_MAGIC;

    type Output = EnhancedPacketBlock<Input::Slice>;

    fn inner_parse<E: ParseError<Input>>(
        block_type: u32,
        block_len1: u32,
        i: Input,
        block_len2: u32,
    ) -> IResult<Input, Self::Output, E> {
        // caller function already tested header type(magic) and length
        // read end of header
        let (i, if_id) = En::parse_u32_gen(i)?;
        let (i, ts_high) = En::parse_u32_gen(i)?;
        let (i, ts_low) = En::parse_u32_gen(i)?;
        let (i, caplen) = En::parse_u32_gen(i)?;
        let (i, origlen) = En::parse_u32_gen(i)?;
        // read packet data
        // align32 can overflow
        if caplen >= ::std::u32::MAX - 4 {
            return Err(ErrMode::Backtrack(E::from_error_kind(i, ErrorKind::Verify)));
        }
        let padded_length = align32!(caplen);
        let (i, data) = take(padded_length)(i)?;
        // read options
        let current_offset = (32 + padded_length) as usize;
        let (i, options) = opt_parse_options::<_, En, E>(i, block_len1 as usize, current_offset)?;
        if block_len2 != block_len1 {
            return Err(ErrMode::Backtrack(E::from_error_kind(i, ErrorKind::Verify)));
        }
        let block = EnhancedPacketBlock {
            block_type,
            block_len1,
            if_id,
            ts_high,
            ts_low,
            caplen,
            origlen,
            data,
            options,
            block_len2,
        };
        Ok((i, block))
    }
}

/// Parse an Enhanced Packet Block (little-endian)
pub fn parse_enhancedpacketblock_le<I>(i: I) -> IResult<I, EnhancedPacketBlock<I>, PcapError<I>>
where
    I: Stream<Token = u8, Slice = I> + StreamIsPartial,
    <I as Stream>::Slice: AsBytes,
{
    ng_block_parser::<I, EnhancedPacketBlock<_>, PcapLE, _, _>().parse_next(i)
}

/// Parse an Enhanced Packet Block (big-endian)
pub fn parse_enhancedpacketblock_be<I>(i: I) -> IResult<I, EnhancedPacketBlock<I>, PcapError<I>>
where
    I: Stream<Token = u8, Slice = I> + StreamIsPartial,
    <I as Stream>::Slice: AsBytes,
{
    ng_block_parser::<I, EnhancedPacketBlock<_>, PcapBE, _, _>().parse_next(i)
}
