use crate::pcap::*;
use crate::pcapng::*;
use cookie_factory::*;
use std::io::Write;

impl PcapHeader {
    pub fn to_vec(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(24);

        let res = gen(
            tuple((
                le_u32(self.magic_number),
                le_u16(self.version_major),
                le_u16(self.version_minor),
                le_i32(self.thiszone),
                le_u32(self.sigfigs),
                le_u32(self.snaplen),
                le_u32(self.network.0 as u32),
            )),
            &mut v,
        )
        .unwrap();
        res.0.to_vec()
    }
}

impl<'a> LegacyPcapBlock<'a> {
    pub fn to_vec(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(self.data.len() + 16);

        let res = gen(
            tuple((
                le_u32(self.ts_sec),
                le_u32(self.ts_usec),
                le_u32(self.caplen),
                le_u32(self.origlen),
                slice(self.data),
            )),
            &mut v,
        )
        .unwrap();
        // pcap records have no alignment constraints
        res.0.to_vec()
    }
}

impl<'a> PcapNGOption<'a> {
    pub fn to_vec(&self) -> Vec<u8> {
        let mut v = Vec::new();
        let res = gen(pcapngoption_le(self), &mut v).unwrap();
        res.0.to_vec()
    }
}

fn pcapngoption_le<'a, 'b: 'a, W: Write + 'a>(i: &'b PcapNGOption) -> impl SerializeFn<W> + 'a {
    tuple((le_u16(i.code.0), le_u16(i.len), slice(i.value)))
}

fn options_length(options: &[PcapNGOption]) -> usize {
    options.iter().map(|o| align32!(4 + o.value.len())).sum()
}

impl<'a> SectionHeaderBlock<'a> {
    /// Serialize to bytes representation. Check values and fix all fields
    pub fn to_vec(&mut self) -> Vec<u8> {
        self.fix();
        self.to_vec_raw()
    }

    /// Check and correct all fields: use magic, version and fix lengths fields
    pub fn fix(&mut self) {
        self.block_type = SHB_MAGIC;
        // XXX bom as BE could be valid
        self.bom = BOM_MAGIC;
        self.major_version = 1;
        self.minor_version = 0;
        // fix length
        let length = (28 + options_length(&self.options)) as u32;
        self.block_len1 = length;
        self.block_len2 = length;
    }

    pub fn to_vec_raw(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(64);
        let res = gen(
            tuple((
                le_u32(self.block_type),
                le_u32(self.block_len1),
                le_u32(self.bom),
                le_u16(self.major_version),
                le_u16(self.minor_version),
                le_i64(self.section_len),
                many_ref(&self.options, pcapngoption_le),
                le_u32(self.block_len2),
            )),
            &mut v,
        )
        .unwrap();
        res.0.to_vec()
    }
}

impl<'a> InterfaceDescriptionBlock<'a> {
    /// Serialize to bytes representation. Check values and fix all fields
    pub fn to_vec(&mut self) -> Vec<u8> {
        self.fix();
        self.to_vec_raw()
    }

    /// Check and correct all fields: use magic, set time resolution and fix lengths fields
    pub fn fix(&mut self) {
        self.block_type = IDB_MAGIC;
        self.reserved = 0;
        // check time resolutopn
        if self.options.last().map(|o| o.code.0 == 0).unwrap_or(false) {
            self.options.pop();
        }
        if !self.options.iter().any(|o| o.code == OptionCode::IfTsresol) {
            self.options.push(PcapNGOption {
                code: OptionCode::IfTsresol,
                len: 1,
                value: &[6, 0, 0, 0],
            });
        }
        if !self
            .options
            .iter()
            .any(|o| o.code == OptionCode::IfTsoffset)
        {
            self.options.push(PcapNGOption {
                code: OptionCode::IfTsoffset,
                len: 8,
                value: &[0, 0, 0, 0, 0, 0, 0, 0],
            });
        }
        self.options.push(PcapNGOption {
            code: OptionCode::EndOfOpt,
            len: 0,
            value: b"",
        });
        // fix length
        let length = (20 + options_length(&self.options)) as u32;
        self.block_len1 = length;
        self.block_len2 = length;
    }

    /// Serialize to bytes representation. Do not check values
    pub fn to_vec_raw(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(64);
        let res = gen(
            tuple((
                le_u32(self.block_type),
                le_u32(self.block_len1),
                le_u16(self.linktype.0 as u16),
                le_u16(self.reserved),
                le_u32(self.snaplen),
                many_ref(&self.options, pcapngoption_le),
                le_u32(self.block_len2),
            )),
            &mut v,
        )
        .unwrap();
        res.0.to_vec()
    }
}

impl<'a> EnhancedPacketBlock<'a> {
    /// Serialize to bytes representation. Check values and fix all fields
    pub fn to_vec(&mut self) -> Vec<u8> {
        self.fix();
        self.to_vec_raw()
    }

    /// Check and correct all fields: use magic, version and fix lengths fields
    pub fn fix(&mut self) {
        self.block_type = EPB_MAGIC;
        self.if_id = 0;
        // fix length
        let length = (32 + self.data.len() + options_length(&self.options)) as u32;
        self.block_len1 = align32!(length);
        self.block_len2 = self.block_len1;
    }

    pub fn to_vec_raw(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(64);
        let al_len = align32!(self.data.len());
        let diff = al_len - self.data.len();
        let padding = if diff > 0 { &[0, 0, 0, 0][..diff] } else { b"" };
        let res = gen(
            tuple((
                le_u32(self.block_type),
                le_u32(self.block_len1),
                le_u32(self.if_id),
                le_u32(self.ts_high),
                le_u32(self.ts_low),
                le_u32(self.caplen),
                le_u32(self.origlen),
                slice(self.data),
                slice(padding),
                many_ref(&self.options, pcapngoption_le),
                le_u32(self.block_len2),
            )),
            &mut v,
        )
        .unwrap();
        res.0.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use crate::pcap::tests::PCAP_HDR;
    use crate::pcap::{parse_pcap_frame, parse_pcap_header};
    use crate::pcapng::*;
    use crate::traits::tests::{FRAME_PCAP, FRAME_PCAPNG_EPB, FRAME_PCAPNG_EPB_WITH_OPTIONS};
    use crate::Linktype;

    #[test]
    fn test_serialize_pcap_header() {
        let (rem, hdr) = parse_pcap_header(PCAP_HDR).expect("header parsing failed");
        assert!(rem.is_empty());
        assert_eq!(hdr.magic_number, 0xa1b2c3d4);
        assert_eq!(hdr.version_major, 2);
        assert_eq!(hdr.version_minor, 4);
        assert_eq!(hdr.snaplen, 262144);
        let v = hdr.to_vec();
        assert_eq!(v.len(), PCAP_HDR.len());
        assert_eq!(v, PCAP_HDR);
    }
    #[test]
    fn test_serialize_pcap_frame() {
        let (rem, pkt) = parse_pcap_frame(FRAME_PCAP).expect("packet parsing failed");
        assert!(rem.is_empty());
        assert_eq!(pkt.origlen, 74);
        assert_eq!(pkt.ts_usec, 562_913);
        assert_eq!(pkt.ts_sec, 1_515_933_236);
        let v = pkt.to_vec();
        println!("self.data.len: {}", pkt.data.len());
        assert_eq!(v.len(), FRAME_PCAP.len());
        assert_eq!(v, FRAME_PCAP);
    }
    #[test]
    fn test_serialize_shb() {
        let shb = SectionHeaderBlock {
            block_type: SHB_MAGIC,
            block_len1: 28,
            bom: BOM_MAGIC,
            major_version: 1,
            minor_version: 0,
            section_len: -1,
            options: Vec::new(),
            block_len2: 28,
        };
        let v = shb.to_vec_raw();
        // println!("shb.to_vec_raw: {:?}", v);
        let res = parse_sectionheaderblock_le(&v);
        assert!(res.is_ok());
    }
    #[test]
    fn test_serialize_shb_options() {
        let shb = SectionHeaderBlock {
            block_type: SHB_MAGIC,
            block_len1: 28 + 8,
            bom: BOM_MAGIC,
            major_version: 1,
            minor_version: 0,
            section_len: -1,
            options: vec![PcapNGOption {
                code: OptionCode(0),
                len: 3,
                value: &[0, 0, 0, 0],
            }],
            block_len2: 28 + 8,
        };
        let v = shb.to_vec_raw();
        // println!("shb.to_vec_raw: {:?}", v);
        let res = parse_sectionheaderblock_le(&v);
        // println!("res: {:?}", res);
        assert!(res.is_ok());
    }
    #[test]
    fn test_serialize_idb() {
        let mut idb = InterfaceDescriptionBlock {
            block_type: IDB_MAGIC,
            block_len1: 20,
            linktype: Linktype::RAW,
            reserved: 0,
            snaplen: 65535,
            options: vec![],
            block_len2: 20,
            if_tsresol: 6,
            if_tsoffset: 0,
        };
        let v = idb.to_vec();
        // println!("idb.to_vec: {:?}", v);
        let res = parse_interfacedescriptionblock(&v);
        assert!(res.is_ok());
    }
    #[test]
    fn test_serialize_epb() {
        let (rem, pkt) = parse_block(FRAME_PCAPNG_EPB).expect("packet creation failed");
        assert!(rem.is_empty());
        if let Block::EnhancedPacket(mut epb) = pkt {
            let v = epb.to_vec();
            // NOTE: v and FRAME_PCAPNG_EPB are different (interface id changes)
            // println!("epb.to_vec: {:?}", v);
            let res = parse_enhancedpacketblock(&v);
            assert!(res.is_ok());
        }
    }
    #[test]
    fn test_serialize_epb_with_options() {
        let (rem, pkt) =
            parse_block(FRAME_PCAPNG_EPB_WITH_OPTIONS).expect("packet creation failed");
        assert!(rem.is_empty());
        if let Block::EnhancedPacket(mut epb) = pkt {
            let v = epb.to_vec();
            // println!("epb.to_vec: {:?}", v);
            let res = parse_enhancedpacketblock(&v);
            assert!(res.is_ok());
        }
    }
}
