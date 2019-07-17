use crate::pcapng::{build_ts, parse_option, PcapNGOption};
use crate::utils::{Data, MICROS_PER_SEC};
use crate::{align32, align_n2, read_u32_e};

/// Container for network data in legacy Pcap files
pub struct LegacyPcapBlock<'a> {
    pub(crate) data: Data<'a>,
    pub(crate) big_endian: bool,
}

impl<'a> LegacyPcapBlock<'a> {
    pub fn new(data: &[u8], big_endian: bool) -> Option<LegacyPcapBlock> {
        if data.len() < 16 {
            return None;
        }
        // XXX read caplen and limit size of data ?
        Some(LegacyPcapBlock {
            data: Data::Borrowed(data),
            big_endian,
        })
    }
    /// The length of the packet as it appeared on the network when it was
    /// captured.
    /// If `cap_len` and `len` differ, the actually saved packet size was
    /// limited by `snaplen`.
    pub fn origlen(&self) -> u32 {
        let start = 12;
        let data = &self.data[start..start + 4];
        read_u32_e!(data, self.big_endian)
    }
    /// The number of bytes of packet data actually captured and saved in the
    /// file.
    pub fn caplen(&self) -> u32 {
        let start = 8;
        let data = &self.data[start..start + 4];
        read_u32_e!(data, self.big_endian)
    }
    /// The date and time when this packet was captured (seconds since epoch).
    pub fn ts_sec(&self) -> u32 {
        let start = 0;
        let data = &self.data[start..start + 4];
        read_u32_e!(data, self.big_endian)
    }
    /// The date and time when this packet was captured (microseconds part).
    pub fn ts_usec(&self) -> u32 {
        let start = 4;
        let data = &self.data[start..start + 4];
        read_u32_e!(data, self.big_endian)
    }
    /// The date and time when this packet was captured (full resolution).
    /// Returns the seconds, fractional part value and unit (in number per second)
    pub fn ts(&self) -> (u32, u32, u64) {
        (self.ts_sec(), self.ts_usec(), MICROS_PER_SEC)
    }
    /// Raw packet data (including header)
    #[inline]
    pub fn raw_data(&self) -> &[u8] {
        self.data.as_slice()
    }
    /// Raw packet header
    #[inline]
    pub fn raw_header(&self) -> &[u8] {
        &self.data[..12]
    }
    /// Network packet data.
    /// Can be shorter than `caplen` if packet does not contain enough data
    #[inline]
    pub fn data(&self) -> &[u8] {
        &self.data[12..]
    }
}

/// Common methods for PcapNG blocks
pub trait PcapNGBlock {
    /// Returns true if block is encoded as big-endian
    #[inline]
    fn big_endian(&self) -> bool;
    /// Raw block data (including header)
    #[inline]
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
    #[inline]
    fn data_len(&self) -> usize;
    /// The inner data, if any
    #[inline]
    fn data(&self) -> &[u8];
    /// The Header length (without options)
    #[inline]
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
        let len = self.data_len() as usize;
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

/// Enhanced Packet Block
///
/// An Enhanced Packet Block (EPB) is the standard container for storing the packets coming from the network.
pub struct EPB<'a> {
    pub(crate) raw_data: Data<'a>,
    pub(crate) big_endian: bool,
    pub(crate) options: Vec<PcapNGOption<'a>>,
}

impl<'a> PcapNGBlock for EPB<'a> {
    #[inline]
    fn raw_data(&self) -> &[u8] {
        self.raw_data.as_slice()
    }
    #[inline]
    fn big_endian(&self) -> bool {
        self.big_endian
    }
    #[inline]
    fn data_len(&self) -> usize {
        let data = &self.raw_data[20..24];
        read_u32_e!(data, self.big_endian) as usize
    }
    #[inline]
    fn data(&self) -> &[u8] {
        &self.raw_data[28..self.data_len()]
    }
    #[inline]
    fn header_len(&self) -> usize {
        28
    }
}

impl<'a> EPB<'a> {
    #[inline]
    pub fn new(data: &[u8], big_endian: bool) -> Option<EPB> {
        if data.len() < 32 {
            return None;
        }
        let block_type = read_u32_e!(data, big_endian);
        if block_type != crate::pcapng::EPB_MAGIC {
            return None;
        }
        // parse options
        let caplen = read_u32_e!(&data[20..24], big_endian) as usize;
        let offset = 28 + align32!(caplen);
        let data_len = data.len();

        let s = &data[offset..data_len - 4];
        // let s : &'a [u8] = self.raw_options();
        let res = many0!(s, complete!(parse_option));
        // println!("res: {:?}", res);
        let options = match res {
            Ok((_rem, res)) => res,
            Err(e) => {
                println!("error: {:?}", e);
                Vec::new()
            }
        };
        Some(EPB {
            raw_data: Data::Borrowed(data),
            big_endian,
            options,
        })
    }
    /// Validate Pcap-NG packet header
    pub fn validate(&self) -> Result<(), &str> {
        let data_len = self.raw_data.len();
        if data_len < 32 {
            return Err("Insufficient data length");
        }
        let block_length1 = read_u32_e!(&self.raw_data[4..], self.big_endian);
        let block_length2 = read_u32_e!(&self.raw_data[data_len - 4..], self.big_endian);
        if block_length1 != block_length2 {
            return Err("Different block length");
        }
        let caplen = self.caplen() as usize;
        if caplen > data_len - 28 {
            return Err("Invalid capture length");
        }
        let origlen = self.origlen() as usize;
        if caplen > origlen {
            return Err("Invalid original length");
        }
        Ok(())
    }
    /// The length of the packet as it appeared on the network when it was
    /// captured.
    /// If `cap_len` and `len` differ, the actually saved packet size was
    /// limited by `snaplen`.
    pub fn origlen(&self) -> u32 {
        let start = 24;
        let data = &self.raw_data[start..start + 4];
        read_u32_e!(data, self.big_endian)
    }
    /// The number of bytes of packet data actually captured and saved in the
    /// file.
    pub fn caplen(&self) -> u32 {
        let start = 20;
        let data = &self.raw_data[start..start + 4];
        read_u32_e!(data, self.big_endian)
    }
    /// The upper 32 bits of the timestamp
    #[inline]
    pub fn ts_high(&self) -> u32 {
        let start = 12;
        let data = &self.raw_data[start..start + 4];
        read_u32_e!(data, self.big_endian)
    }
    /// The lower 32 bits of the timestamp
    #[inline]
    pub fn ts_low(&self) -> u32 {
        let start = 16;
        let data = &self.raw_data[start..start + 4];
        read_u32_e!(data, self.big_endian)
    }
    /// The date and time when this packet was captured (seconds since epoch).
    /// This requires to know the timestamp offset and resolution (which can be found in the
    /// interface description)
    pub fn ts_sec(&self, ts_resol: u8, ts_offset: u64) -> u32 {
        let data = &self.raw_data[12..20];
        let ts_high = read_u32_e!(data, self.big_endian);
        let ts_low = read_u32_e!(&data[4..], self.big_endian);
        // XXX keep in cache ?
        let (ts_sec, _ts_fractional, _ts_unit) = build_ts(ts_high, ts_low, ts_offset, ts_resol);
        ts_sec
    }
    /// The date and time when this packet was captured (microseconds part).
    /// This requires to know the timestamp offset and resolution (which can be found in the
    /// interface description)
    pub fn ts_usec(&self, ts_resol: u8, ts_offset: u64) -> u32 {
        let data = &self.raw_data[12..20];
        let ts_high = read_u32_e!(data, self.big_endian);
        let ts_low = read_u32_e!(&data[4..], self.big_endian);
        // XXX keep in cache ?
        let (_ts_sec, ts_fractional, ts_unit) = build_ts(ts_high, ts_low, ts_offset, ts_resol);
        ts_fractional / ((ts_unit / MICROS_PER_SEC) as u32)
    }
    /// The date and time when this packet was captured (full resolution).
    /// Returns the seconds, fractional part value and unit (in number per second)
    /// This requires to know the timestamp offset and resolution (which can be found in the
    /// interface description)
    pub fn ts(&self, ts_resol: u8, ts_offset: u64) -> (u32, u32, u64) {
        let data = &self.raw_data[12..20];
        let ts_high = read_u32_e!(data, self.big_endian);
        let ts_low = read_u32_e!(&data[4..], self.big_endian);
        // XXX keep in cache ?
        let (ts_sec, ts_fractional, ts_unit) = build_ts(ts_high, ts_low, ts_offset, ts_resol);
        (ts_sec, ts_fractional, ts_unit)
    }
    /// The identifier of interface where the packet was captured
    #[inline]
    pub fn interface(&self) -> u32 {
        let start = 8;
        let data = &self.raw_data[start..start + 4];
        read_u32_e!(data, self.big_endian)
    }
    /// Network packet data
    /// Can be shorter than caplen if packet does not contain enough data
    #[inline]
    pub fn data(&self) -> &[u8] {
        let mut caplen = self.caplen() as usize;
        // if requested length is too big, truncate
        if caplen > self.raw_data.len() - 28 {
            caplen = self.raw_data.len() - 28;
        }
        &self.raw_data[28..28 + caplen]
    }
    /// The options of this block, if any
    pub fn options(&self) -> &[PcapNGOption<'a>] {
        &self.options
    }
}

/* ******************* */

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::pcapng::traits_parse_enhancedpacketblock;
    // tls12-23.pcap frame 0
    pub const FRAME_PCAP: &'static [u8] = &hex!(
        "
34 4E 5B 5A E1 96 08 00 4A 00 00 00 4A 00 00 00
72 4D 4A D1 13 0D 4E 9C AE DE CB 73 08 00 45 00
00 3C DF 08 40 00 40 06 47 9F 0A 09 00 01 0A 09
00 02 D1 F4 11 51 34 1B 5B 17 00 00 00 00 A0 02
72 10 14 43 00 00 02 04 05 B4 04 02 08 0A E4 DB
6B 7B 00 00 00 00 01 03 03 07"
    );
    // OpenVPN_UDP_tls-auth.pcapng EPB (first data block, file block 3)
    pub const FRAME_PCAPNG_EPB: &'static [u8] = &hex!(
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
    pub const FRAME_PCAPNG_EPB_WITH_OPTIONS: &'static [u8] = &hex!(
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

    #[test]
    fn test_data() {
        let d = Data::Borrowed(&[0, 1, 2, 3]);
        assert_eq!(d.as_ref()[1], 1);
        assert_eq!(d[1], 1);
        assert_eq!(&d[1..=2], &[1, 2]);
    }
    #[test]
    fn test_pcap_packet_functions() {
        let pkt = LegacyPcapBlock::new(FRAME_PCAP, false).expect("packet creation failed");
        assert_eq!(pkt.origlen(), 74);
        assert_eq!(pkt.ts_usec(), 562_913);
        assert_eq!(pkt.ts_sec(), 1_515_933_236);
    }
    #[test]
    fn test_pcapng_packet_functions() {
        let pkt = EPB::new(FRAME_PCAPNG_EPB, false).expect("packet creation failed");
        assert_eq!(pkt.interface(), 1);
        assert_eq!(pkt.origlen(), 84);
        assert_eq!(pkt.data().len(), 84);
        assert!(pkt.raw_options().is_empty());
        assert!(pkt.validate().is_ok());
    }
    #[test]
    fn test_pcapng_packet_epb_with_options() {
        let pkt = EPB::new(FRAME_PCAPNG_EPB_WITH_OPTIONS, false).expect("packet creation failed");
        assert_eq!(pkt.interface(), 0);
        assert_eq!(pkt.origlen(), 314);
        assert_eq!(pkt.data().len(), 314);
        // use nom::HexDisplay;
        // println!("raw_options:\n{}", pkt.raw_options().to_hex(16));
    }
    #[test]
    fn test_parse_enhancepacketblock() {
        let (rem, pkt) = traits_parse_enhancedpacketblock(FRAME_PCAPNG_EPB_WITH_OPTIONS)
            .expect("packet parsing failed");
        assert!(rem.is_empty());
        assert_eq!(pkt.interface(), 0);
        assert_eq!(pkt.origlen(), 314);
        assert_eq!(pkt.data().len(), 314);
        println!("options: {:?}", pkt.options());
        // use nom::HexDisplay;
        // println!("raw_options:\n{}", pkt.raw_options().to_hex(16));
    }
}
