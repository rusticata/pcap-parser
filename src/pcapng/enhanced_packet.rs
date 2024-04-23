use nom::bytes::streaming::take;
use nom::error::{ErrorKind, ParseError};
use nom::{Err, IResult};
use rusticata_macros::align32;

use crate::endianness::{PcapBE, PcapEndianness, PcapLE};
use crate::traits::PcapNGPacketBlock;
use crate::utils::array_ref4;
use crate::{build_ts, build_ts_f64, opt_parse_options, PcapError, PcapNGOption, EPB_MAGIC};

use super::*;

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
/// # let input_data = include_bytes!("../../assets/test001-le.pcapng");
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
pub struct EnhancedPacketBlock<'a> {
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
    pub data: &'a [u8],
    pub options: Vec<PcapNGOption<'a>>,
    pub block_len2: u32,
}

impl<'a> EnhancedPacketBlock<'a> {
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

impl<'a> PcapNGPacketBlock for EnhancedPacketBlock<'a> {
    fn big_endian(&self) -> bool {
        self.block_type != EPB_MAGIC
    }
    fn truncated(&self) -> bool {
        self.origlen != self.caplen
    }
    fn orig_len(&self) -> u32 {
        self.origlen
    }
    fn raw_packet_data(&self) -> &[u8] {
        self.data
    }
    fn packet_data(&self) -> &[u8] {
        let caplen = self.caplen as usize;
        if caplen < self.data.len() {
            &self.data[..caplen]
        } else {
            self.data
        }
    }
}

impl<'a, En: PcapEndianness> PcapNGBlockParser<'a, En, EnhancedPacketBlock<'a>>
    for EnhancedPacketBlock<'a>
{
    const HDR_SZ: usize = 32;
    const MAGIC: u32 = EPB_MAGIC;

    fn inner_parse<E: ParseError<&'a [u8]>>(
        block_type: u32,
        block_len1: u32,
        i: &'a [u8],
        block_len2: u32,
    ) -> IResult<&'a [u8], EnhancedPacketBlock<'a>, E> {
        // caller function already tested header type(magic) and length
        // read end of header
        let (b_hdr, packet_data) = i.split_at(20);
        let if_id = En::u32_from_bytes(*array_ref4(b_hdr, 0));
        let ts_high = En::u32_from_bytes(*array_ref4(b_hdr, 4));
        let ts_low = En::u32_from_bytes(*array_ref4(b_hdr, 8));
        let caplen = En::u32_from_bytes(*array_ref4(b_hdr, 12));
        let origlen = En::u32_from_bytes(*array_ref4(b_hdr, 16));
        // read packet data
        // align32 can overflow
        if caplen >= u32::MAX - 4 {
            return Err(Err::Error(E::from_error_kind(i, ErrorKind::Verify)));
        }
        let padded_length = align32!(caplen);
        let (i, data) = take(padded_length)(packet_data)?;
        // read options
        let current_offset = (32 + padded_length) as usize;
        let (i, options) = opt_parse_options::<En, E>(i, block_len1 as usize, current_offset)?;
        if block_len2 != block_len1 {
            return Err(Err::Error(E::from_error_kind(i, ErrorKind::Verify)));
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
pub fn parse_enhancedpacketblock_le(
    i: &[u8],
) -> IResult<&[u8], EnhancedPacketBlock, PcapError<&[u8]>> {
    ng_block_parser::<EnhancedPacketBlock, PcapLE, _, _>()(i)
}

/// Parse an Enhanced Packet Block (big-endian)
pub fn parse_enhancedpacketblock_be(
    i: &[u8],
) -> IResult<&[u8], EnhancedPacketBlock, PcapError<&[u8]>> {
    ng_block_parser::<EnhancedPacketBlock, PcapBE, _, _>()(i)
}
