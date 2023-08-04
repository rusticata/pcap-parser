use crate::blocks::PcapBlockOwned;
use crate::error::PcapError;
use crate::read_u32_e;
use rusticata_macros::align32;

/// Common methods for PcapNG blocks
pub trait PcapNGBlock {
    /// Returns true if block is encoded as big-endian
    fn big_endian(&self) -> bool;
    /// Raw block data (including header)
    fn raw_data(&self) -> &[u8];
    /// The type of this block
    #[inline]
    fn block_type(&self) -> u32 {
        read_u32_e!(&self.raw_data(), self.big_endian())
    }
    /// The block length from the block header
    #[inline]
    fn block_length(&self) -> u32 {
        read_u32_e!(&self.raw_data()[4..8], self.big_endian())
    }
    /// The block length from the block footer
    #[inline]
    fn block_length2(&self) -> u32 {
        let data = self.raw_data();
        let data_len = data.len();
        read_u32_e!(&data[data_len - 4..], self.big_endian())
    }
    /// The length of inner data, if any
    fn data_len(&self) -> usize;
    /// The inner data, if any
    fn data(&self) -> &[u8];
    /// The Header length (without options)
    fn header_len(&self) -> usize;
    /// Raw packet header (without options)
    #[inline]
    fn raw_header(&self) -> &[u8] {
        let len = self.header_len();
        &self.raw_data()[..len]
    }
    /// Return the declared offset of options.
    /// *Warning: the offset can be out of bounds, caller must test value before accessing data*
    #[inline]
    fn offset_options(&self) -> usize {
        let len = self.data_len();
        self.header_len() + align32!(len)
    }
    /// Network packet options.
    /// Can be empty if packet does not contain options
    #[inline]
    fn raw_options(&self) -> &[u8] {
        let offset = self.offset_options();
        let data_len = self.data_len();
        // if requested length is too big, truncate
        if offset + 4 >= data_len {
            return &[];
        }
        &self.raw_data()[offset..data_len - 4]
    }
}

/// Common methods for PcapNG Packet blocks
pub trait PcapNGPacketBlock {
    /// Return true if block is encoded as big-endian
    fn big_endian(&self) -> bool;
    /// Return true if block data was truncated (typically when snaplen < origlen)
    fn truncated(&self) -> bool {
        false
    }
    /// Return the original length of the packet
    fn orig_len(&self) -> u32;
    /// Return the raw captured packet data, with padding if present, and eventually truncated.
    fn raw_packet_data(&self) -> &[u8];
    /// Return the captured packet data without padding
    ///
    /// If packet was truncated, the truncated data field is returned.
    fn packet_data(&self) -> &[u8];
}

/// Streaming Iterator over pcap files
///
/// Implementors of this trait are usually based on a circular buffer, which means memory
/// usage is constant, and that it can be used to parse huge files or infinite streams.
/// However, this also means some care must be taken so no reference (for ex a pcap block) is
/// kept on the buffer before changing the buffer content.
///
/// Each call to `next` will return the next block,
/// and must be followed by call to `consume` to avoid reading the same data.
/// `consume` takes care of shifting data in the buffer if required, but does not refill it.
///
/// It is possible to read multiple blocks before consuming data.
/// Call `consume_noshift` instead of `consume`. To refill the buffer, first ensures that you do
/// not keep any reference over internal data (blocks or slices), and call `refill`.
///
/// To determine when a refill is needed, either test `next()` for an incomplete read. You can also
/// use `position` to implement a heuristic refill (for ex, when `position > capacity / 2`.
///
/// **The blocks already read, and underlying data, must be discarded before calling
/// `consume` or `refill`.** It is the caller's responsibility to call functions in the correct
/// order.
pub trait PcapReaderIterator {
    /// Get the next pcap block, if possible. Returns the number of bytes read and the block.
    ///
    /// The returned object is valid until `consume` or `refill` is called.
    fn next(&mut self) -> Result<(usize, PcapBlockOwned), PcapError<&[u8]>>;
    /// Consume data, and shift buffer if needed.
    ///
    /// If the position gets past the buffer's half, this will move the remaining data to the
    /// beginning of the buffer.
    ///
    /// **The blocks already read, and underlying data, must be discarded before calling
    /// this function.**
    fn consume(&mut self, offset: usize);
    /// Consume date, but do not change the buffer. Blocks already read are still valid.
    fn consume_noshift(&mut self, offset: usize);
    /// Get the number of consumed bytes
    fn consumed(&self) -> usize;
    /// Refill the internal buffer, shifting it if necessary.
    ///
    /// **The blocks already read, and underlying data, must be discarded before calling
    /// this function.**
    fn refill(&mut self) -> Result<(), PcapError<&[u8]>>;
    /// Get the position in the internal buffer. Can be used to determine if `refill` is required.
    fn position(&self) -> usize;
    /// Grow size of the internal buffer.
    fn grow(&mut self, new_size: usize) -> bool;
    /// Returns a slice with all the available data
    fn data(&self) -> &[u8];
    /// Returns true if underlying reader is exhausted
    ///
    /// Note that exhausted reader only means that next `refill` will not
    /// add any data, but there can still be data not consumed in the current buffer.
    fn reader_exhausted(&self) -> bool;
}

/* ******************* */

#[cfg(test)]
pub mod tests {
    use crate::pcap::parse_pcap_frame;
    use crate::pcapng::{parse_block_le, Block, SecretsType};
    use crate::traits::PcapNGPacketBlock;
    use crate::utils::Data;
    use hex_literal::hex;
    // tls12-23.pcap frame 0
    pub const FRAME_PCAP: &[u8] = &hex!(
        "
34 4E 5B 5A E1 96 08 00 4A 00 00 00 4A 00 00 00
72 4D 4A D1 13 0D 4E 9C AE DE CB 73 08 00 45 00
00 3C DF 08 40 00 40 06 47 9F 0A 09 00 01 0A 09
00 02 D1 F4 11 51 34 1B 5B 17 00 00 00 00 A0 02
72 10 14 43 00 00 02 04 05 B4 04 02 08 0A E4 DB
6B 7B 00 00 00 00 01 03 03 07"
    );
    // OpenVPN_UDP_tls-auth.pcapng EPB (first data block, file block 3)
    pub const FRAME_PCAPNG_EPB: &[u8] = &hex!(
        "
06 00 00 00 74 00 00 00 01 00 00 00 E9 D3 04 00
48 EE 39 44 54 00 00 00 54 00 00 00 08 00 27 4A
BE 45 08 00 27 BB 22 84 08 00 45 00 00 46 00 00
40 00 40 11 48 89 C0 A8 38 67 C0 A8 38 66 81 AE
04 AA 00 32 53 B4 38 81 38 14 62 1D 67 46 2D DE
86 73 4D 2C BF F1 51 B2 B1 23 1B 61 E4 23 08 A2
72 81 8E 00 00 00 01 50 FF 26 2C 00 00 00 00 00
74 00 00 00"
    );
    // test009.pcapng EPB (first data block)
    pub const FRAME_PCAPNG_EPB_WITH_OPTIONS: &[u8] = &hex!(
        "
06 00 00 00 F4 01 00 00 00 00 00 00 97 C3 04 00
AA 47 CA 64 3A 01 00 00 3A 01 00 00 FF FF FF FF
FF FF 00 0B 82 01 FC 42 08 00 45 00 01 2C A8 36
00 00 FA 11 17 8B 00 00 00 00 FF FF FF FF 00 44
00 43 01 18 59 1F 01 01 06 00 00 00 3D 1D 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 0B 82 01 FC 42 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 63 82 53 63 35 01 01 3D 07 01 00 0B 82 01
FC 42 32 04 00 00 00 00 37 04 01 03 06 2A FF 00
00 00 00 00 00 00 00 00 01 00 09 00 74 65 73 74
30 30 39 2D 31 00 00 00 02 00 04 00 00 00 00 00
04 00 08 00 00 00 00 00 00 00 00 00 AC 0B 0D 00
61 20 66 61 6B 65 20 73 74 72 69 6E 67 00 00 00
AD 0B 0F 00 73 6F 6D 65 20 66 61 6B 65 20 62 79
74 65 73 00 AC 4B 0E 00 6D 79 20 66 61 6B 65 20
73 74 72 69 6E 67 00 00 AD 4B 0D 00 6D 79 20 66
61 6B 65 20 62 79 74 65 73 00 00 00 23 01 0C 00
74 72 79 20 74 68 69 73 20 6F 6E 65 23 81 0C 00
61 6E 64 20 74 68 69 73 20 6F 6E 65 00 00 00 00
F4 01 00 00"
    );
    // block 3 from file dtls12-aes128ccm8-dsb.pcapng (wireshark repo)
    pub const FRAME_PCAPNG_DSB: &[u8] = &hex!(
        "
0a 00 00 00 c4 00 00 00 4b 53 4c 54 b0 00 00 00
43 4c 49 45 4e 54 5f 52 41 4e 44 4f 4d 20 35 38
38 65 35 66 39 64 63 37 37 38 63 65 66 32 32 34
30 35 66 34 32 66 39 62 65 61 32 35 39 32 38 62
64 30 33 31 32 63 65 31 34 64 36 34 32 64 30 33
34 64 32 34 66 34 66 61 62 36 37 32 66 63 20 37
30 35 37 66 33 64 37 30 36 63 66 30 36 38 30 61
34 30 65 34 66 32 65 30 37 34 37 63 65 37 38 63
65 39 38 64 61 32 36 32 32 65 62 39 61 39 35 34
33 66 37 66 31 35 34 36 33 37 34 34 31 35 37 32
35 36 61 37 39 36 64 62 35 30 62 62 65 36 35 63
64 62 64 63 32 39 32 61 30 39 33 33 35 62 34 0a
c4 00 00 00"
    );
    // SHB of test/captures/http-brotli.pcapng from wireshark repo
    pub const FRAME_PCAPNG_SHB: &[u8] = &hex!(
        "
0a 0d 0d 0a c4 00 00 00 4d 3c 2b 1a 01 00 00 00
ff ff ff ff ff ff ff ff 02 00 37 00 49 6e 74 65
6c 28 52 29 20 43 6f 72 65 28 54 4d 29 20 69 37
2d 36 37 30 30 48 51 20 43 50 55 20 40 20 32 2e
36 30 47 48 7a 20 28 77 69 74 68 20 53 53 45 34
2e 32 29 00 03 00 2a 00 4c 69 6e 75 78 20 34 2e
32 30 2e 31 32 2d 67 65 6e 74 6f 6f 2d 61 6e 64
72 6f 6d 65 64 61 2d 32 30 31 39 30 33 30 35 2d
76 31 00 00 04 00 33 00 44 75 6d 70 63 61 70 20
28 57 69 72 65 73 68 61 72 6b 29 20 33 2e 31 2e
30 20 28 76 33 2e 31 2e 30 72 63 30 2d 34 36 38
2d 67 65 33 65 34 32 32 32 62 29 00 00 00 00 00
c4 00 00 00"
    );

    #[test]
    fn test_data() {
        let d = Data::Borrowed(&[0, 1, 2, 3]);
        assert_eq!(d.as_ref()[1], 1);
        assert_eq!(d[1], 1);
        assert_eq!(&d[1..=2], &[1, 2]);
    }
    #[test]
    fn test_pcap_packet_functions() {
        let (_, pkt) = parse_pcap_frame(FRAME_PCAP).expect("packet creation failed");
        assert_eq!(pkt.origlen, 74);
        assert_eq!(pkt.ts_usec, 562_913);
        assert_eq!(pkt.ts_sec, 1_515_933_236);
    }
    #[test]
    fn test_pcapng_packet_functions() {
        let (rem, pkt) = parse_block_le(FRAME_PCAPNG_EPB).expect("packet creation failed");
        assert!(rem.is_empty());
        if let Block::EnhancedPacket(epb) = pkt {
            assert_eq!(epb.if_id, 1);
            assert_eq!(epb.origlen, 84);
            assert_eq!(epb.data.len(), 84);
            assert!(epb.options.is_empty());
        }
    }
    #[test]
    fn test_pcapng_packet_epb_with_options() {
        let (rem, pkt) =
            parse_block_le(FRAME_PCAPNG_EPB_WITH_OPTIONS).expect("packet creation failed");
        assert!(rem.is_empty());
        if let Block::EnhancedPacket(epb) = pkt {
            assert_eq!(epb.if_id, 0);
            assert_eq!(epb.origlen, 314);
            assert_eq!(epb.data.len(), 316); // with padding
            assert_eq!(epb.packet_data().len(), 314); // without padding
        }
    }
    #[test]
    fn test_parse_enhancepacketblock() {
        let (rem, pkt) =
            parse_block_le(FRAME_PCAPNG_EPB_WITH_OPTIONS).expect("packet parsing failed");
        assert!(rem.is_empty());
        if let Block::EnhancedPacket(epb) = pkt {
            assert_eq!(epb.if_id, 0);
            assert_eq!(epb.origlen, 314);
            assert_eq!(epb.data.len(), 316); // with padding
            assert_eq!(epb.packet_data().len(), 314); // without padding
            println!("options: {:?}", epb.options);
        // use nom::HexDisplay;
        // println!("raw_options:\n{}", pkt.raw_options().to_hex(16));
        } else {
            panic!("wrong packet type");
        }
    }

    #[test]
    fn test_pcapng_decryptionsecretsblock() {
        let (rem, block) = parse_block_le(FRAME_PCAPNG_DSB).expect("could not parse DSB");
        assert!(rem.is_empty());
        if let Block::DecryptionSecrets(dsb) = block {
            assert_eq!(dsb.secrets_type, SecretsType::TlsKeyLog);
            assert!(std::str::from_utf8(dsb.data).is_ok());
        } else {
            unreachable!();
        }
    }
}
