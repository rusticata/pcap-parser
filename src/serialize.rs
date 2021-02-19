use crate::pcap::*;
use crate::pcapng::*;
use cookie_factory::bytes::{le_i32, le_i64, le_u16, le_u32};
use cookie_factory::combinator::slice;
use cookie_factory::multi::many_ref;
use cookie_factory::sequence::tuple;
use cookie_factory::{gen, GenError, SerializeFn};
use rusticata_macros::align32;
use std::io::Write;

/// Common trait for all serialization functions
pub trait ToVec {
    /// Serialize to bytes representation (little-endian).
    /// Check values and fix all fields before serializing.
    fn to_vec(&mut self) -> Result<Vec<u8>, GenError> {
        self.fix();
        self.to_vec_raw()
    }

    /// Check and correct all fields: use magic, fix lengths fields and other values if possible.
    fn fix(&mut self) {}

    /// Serialize to bytes representation (little-endian). Do not check values
    fn to_vec_raw(&self) -> Result<Vec<u8>, GenError>;
}

impl ToVec for PcapHeader {
    fn to_vec_raw(&self) -> Result<Vec<u8>, GenError> {
        let mut v = Vec::with_capacity(24);

        gen(
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
        .map(|res| res.0.to_vec())
    }
}

impl<'a> ToVec for LegacyPcapBlock<'a> {
    fn to_vec_raw(&self) -> Result<Vec<u8>, GenError> {
        let mut v = Vec::with_capacity(self.data.len() + 16);

        gen(
            tuple((
                le_u32(self.ts_sec),
                le_u32(self.ts_usec),
                le_u32(self.caplen),
                le_u32(self.origlen),
                slice(self.data),
            )),
            &mut v,
        )
        // pcap records have no alignment constraints
        .map(|res| res.0.to_vec())
    }
}

impl<'a> ToVec for PcapNGOption<'a> {
    fn to_vec_raw(&self) -> Result<Vec<u8>, GenError> {
        let mut v = Vec::new();
        gen(pcapngoption_le(self), &mut v).map(|res| res.0.to_vec())
    }
}

fn pcapngoption_le<'a, 'b: 'a, W: Write + 'a>(i: &'b PcapNGOption) -> impl SerializeFn<W> + 'a {
    tuple((le_u16(i.code.0), le_u16(i.len), slice(i.value)))
}

fn options_length(options: &[PcapNGOption]) -> usize {
    options.iter().map(|o| align32!(4 + o.value.len())).sum()
}

impl<'a> ToVec for SectionHeaderBlock<'a> {
    /// Check and correct all fields: use magic, version and fix lengths fields
    fn fix(&mut self) {
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

    fn to_vec_raw(&self) -> Result<Vec<u8>, GenError> {
        let mut v = Vec::with_capacity(64);
        gen(
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
        .map(|res| res.0.to_vec())
    }
}

impl<'a> ToVec for InterfaceDescriptionBlock<'a> {
    /// Check and correct all fields: use magic, set time resolution and fix lengths fields
    fn fix(&mut self) {
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
    fn to_vec_raw(&self) -> Result<Vec<u8>, GenError> {
        let mut v = Vec::with_capacity(64);
        gen(
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
        .map(|res| res.0.to_vec())
    }
}

impl<'a> ToVec for EnhancedPacketBlock<'a> {
    /// Check and correct all fields: use magic, version and fix lengths fields
    fn fix(&mut self) {
        self.block_type = EPB_MAGIC;
        self.if_id = 0;
        // fix length
        let length = (32 + self.data.len() + options_length(&self.options)) as u32;
        self.block_len1 = align32!(length);
        self.block_len2 = self.block_len1;
    }

    fn to_vec_raw(&self) -> Result<Vec<u8>, GenError> {
        let mut v = Vec::with_capacity(64);
        let al_len = align32!(self.data.len());
        let diff = al_len - self.data.len();
        let padding = if diff > 0 { &[0, 0, 0, 0][..diff] } else { b"" };
        gen(
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
        .map(|res| res.0.to_vec())
    }
}

impl<'a> ToVec for SimplePacketBlock<'a> {
    fn fix(&mut self) {
        self.block_type = SPB_MAGIC;
        // fix length
        self.block_len1 = (16 + align32!(self.data.len())) as u32;
        self.block_len2 = self.block_len1;
    }

    fn to_vec_raw(&self) -> Result<Vec<u8>, GenError> {
        let mut v = Vec::with_capacity(64);
        let al_len = align32!(self.data.len());
        let diff = al_len - self.data.len();
        let padding = if diff > 0 { &[0, 0, 0, 0][..diff] } else { b"" };
        gen(
            tuple((
                le_u32(self.block_type),
                le_u32(self.block_len1),
                le_u32(self.origlen),
                slice(self.data),
                slice(padding),
                le_u32(self.block_len2),
            )),
            &mut v,
        )
        .map(|res| res.0.to_vec())
    }
}

fn namerecord_le<'a, 'b: 'a, W: Write + 'a>(i: &'b NameRecord) -> impl SerializeFn<W> + 'a {
    tuple((
        le_u16(i.record_type.0),
        le_u16(i.record_value.len() as u16),
        slice(i.record_value),
    ))
}

fn namerecords_length(nr: &[NameRecord]) -> usize {
    nr.iter().map(|n| align32!(2 + n.record_value.len())).sum()
}

impl<'a> ToVec for NameResolutionBlock<'a> {
    fn fix(&mut self) {
        self.block_type = NRB_MAGIC;
        // fix length
        let length = (12 + namerecords_length(&self.nr) + options_length(&self.options)) as u32;
        self.block_len1 = align32!(length);
        self.block_len2 = self.block_len1;
    }

    fn to_vec_raw(&self) -> Result<Vec<u8>, GenError> {
        let mut v = Vec::with_capacity(64);
        gen(
            tuple((
                le_u32(self.block_type),
                le_u32(self.block_len1),
                many_ref(&self.nr, namerecord_le),
                many_ref(&self.options, pcapngoption_le),
                le_u32(self.block_len2),
            )),
            &mut v,
        )
        .map(|res| res.0.to_vec())
    }
}

impl<'a> ToVec for InterfaceStatisticsBlock<'a> {
    fn fix(&mut self) {
        self.block_type = ISB_MAGIC;
        // fix length
        self.block_len1 = (24 + align32!(options_length(&self.options))) as u32;
        self.block_len2 = self.block_len1;
    }

    fn to_vec_raw(&self) -> Result<Vec<u8>, GenError> {
        let mut v = Vec::with_capacity(64);
        gen(
            tuple((
                le_u32(self.block_type),
                le_u32(self.block_len1),
                le_u32(self.if_id),
                le_u32(self.ts_high),
                le_u32(self.ts_low),
                many_ref(&self.options, pcapngoption_le),
                le_u32(self.block_len2),
            )),
            &mut v,
        )
        .map(|res| res.0.to_vec())
    }
}

impl<'a> ToVec for SystemdJournalExportBlock<'a> {
    fn fix(&mut self) {
        if self.block_type != SJE_MAGIC {
            self.block_type = SJE_MAGIC;
        }
        // fix length
        self.block_len1 = (12 + align32!(self.data.len())) as u32;
        self.block_len2 = self.block_len1;
    }

    fn to_vec_raw(&self) -> Result<Vec<u8>, GenError> {
        let mut v = Vec::with_capacity(64);
        let al_len = align32!(self.data.len());
        let diff = al_len - self.data.len();
        let padding = if diff > 0 { &[0, 0, 0, 0][..diff] } else { b"" };
        gen(
            tuple((
                le_u32(self.block_type),
                le_u32(self.block_len1),
                slice(self.data),
                slice(padding),
                le_u32(self.block_len2),
            )),
            &mut v,
        )
        .map(|res| res.0.to_vec())
    }
}

impl<'a> ToVec for DecryptionSecretsBlock<'a> {
    fn fix(&mut self) {
        if self.block_type != DSB_MAGIC {
            self.block_type = DSB_MAGIC;
        }
        // fix length
        self.block_len1 = (24 + align32!(self.data.len())) as u32;
        self.block_len2 = self.block_len1;
    }

    fn to_vec_raw(&self) -> Result<Vec<u8>, GenError> {
        let mut v = Vec::with_capacity(64);
        let al_len = align32!(self.data.len());
        let diff = al_len - self.data.len();
        let padding = if diff > 0 { &[0, 0, 0, 0][..diff] } else { b"" };
        gen(
            tuple((
                le_u32(self.block_type),
                le_u32(self.block_len1),
                le_u32(self.secrets_type.0),
                le_u32(self.secrets_len),
                slice(self.data),
                slice(padding),
                many_ref(&self.options, pcapngoption_le),
                le_u32(self.block_len2),
            )),
            &mut v,
        )
        .map(|res| res.0.to_vec())
    }
}

impl<'a> ToVec for CustomBlock<'a> {
    fn fix(&mut self) {
        if self.block_type != DCB_MAGIC && self.block_type != CB_MAGIC {
            self.block_type = CB_MAGIC;
        }
        // fix length
        self.block_len1 = (20 + align32!(self.data.len())) as u32;
        self.block_len2 = self.block_len1;
    }

    fn to_vec_raw(&self) -> Result<Vec<u8>, GenError> {
        let mut v = Vec::with_capacity(64);
        let al_len = align32!(self.data.len());
        let diff = al_len - self.data.len();
        let padding = if diff > 0 { &[0, 0, 0, 0][..diff] } else { b"" };
        gen(
            tuple((
                le_u32(self.block_type),
                le_u32(self.block_len1),
                le_u32(self.pen),
                slice(self.data),
                slice(padding),
                le_u32(self.block_len2),
            )),
            &mut v,
        )
        .map(|res| res.0.to_vec())
    }
}

impl<'a> ToVec for UnknownBlock<'a> {
    fn fix(&mut self) {
        // do not touch type, it is unknown
        // fix length
        self.block_len1 = (12 + align32!(self.data.len())) as u32;
        self.block_len2 = self.block_len1;
    }

    fn to_vec_raw(&self) -> Result<Vec<u8>, GenError> {
        let mut v = Vec::new();
        let al_len = align32!(self.data.len());
        let diff = al_len - self.data.len();
        let padding = if diff > 0 { &[0, 0, 0, 0][..diff] } else { b"" };
        gen(
            tuple((
                le_u32(self.block_type),
                le_u32(self.block_len1),
                slice(self.data),
                slice(padding),
                le_u32(self.block_len2),
            )),
            &mut v,
        )
        .map(|res| res.0.to_vec())
    }
}

impl<'a> ToVec for Block<'a> {
    fn fix(&mut self) {
        match self {
            Block::SectionHeader(b) => b.fix(),
            Block::InterfaceDescription(b) => b.fix(),
            Block::EnhancedPacket(b) => b.fix(),
            Block::SimplePacket(b) => b.fix(),
            Block::NameResolution(b) => b.fix(),
            Block::InterfaceStatistics(b) => b.fix(),
            Block::SystemdJournalExport(b) => b.fix(),
            Block::DecryptionSecrets(b) => b.fix(),
            Block::Custom(b) => b.fix(),
            Block::Unknown(b) => b.fix(),
        }
    }

    fn to_vec_raw(&self) -> Result<Vec<u8>, GenError> {
        match self {
            Block::SectionHeader(b) => b.to_vec_raw(),
            Block::InterfaceDescription(b) => b.to_vec_raw(),
            Block::EnhancedPacket(b) => b.to_vec_raw(),
            Block::SimplePacket(b) => b.to_vec_raw(),
            Block::NameResolution(b) => b.to_vec_raw(),
            Block::InterfaceStatistics(b) => b.to_vec_raw(),
            Block::SystemdJournalExport(b) => b.to_vec_raw(),
            Block::DecryptionSecrets(b) => b.to_vec_raw(),
            Block::Custom(b) => b.to_vec_raw(),
            Block::Unknown(b) => b.to_vec_raw(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::pcap::tests::PCAP_HDR;
    use crate::pcap::{parse_pcap_frame, parse_pcap_header};
    use crate::pcapng::*;
    use crate::serialize::ToVec;
    use crate::traits::tests::{
        FRAME_PCAP, FRAME_PCAPNG_DSB, FRAME_PCAPNG_EPB, FRAME_PCAPNG_EPB_WITH_OPTIONS,
    };
    use crate::Linktype;

    #[test]
    fn test_serialize_pcap_header() {
        let (rem, hdr) = parse_pcap_header(PCAP_HDR).expect("header parsing failed");
        assert!(rem.is_empty());
        assert_eq!(hdr.magic_number, 0xa1b2_c3d4);
        assert_eq!(hdr.version_major, 2);
        assert_eq!(hdr.version_minor, 4);
        assert_eq!(hdr.snaplen, 262_144);
        let v = hdr.to_vec_raw().expect("serialize");
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
        let v = pkt.to_vec_raw().expect("serialize");
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
        let v = shb.to_vec_raw().expect("serialize");
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
        let v = shb.to_vec_raw().expect("serialize");
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
        let v = idb.to_vec().expect("serialize");
        // println!("idb.to_vec: {:?}", v);
        let res = parse_interfacedescriptionblock_le(&v);
        assert!(res.is_ok());
    }
    #[test]
    fn test_serialize_epb() {
        let (rem, pkt) = parse_block_le(FRAME_PCAPNG_EPB).expect("packet creation failed");
        assert!(rem.is_empty());
        if let Block::EnhancedPacket(mut epb) = pkt {
            let v = epb.to_vec().expect("serialize");
            // NOTE: v and FRAME_PCAPNG_EPB are different (interface id changes)
            // println!("epb.to_vec: {:?}", v);
            let res = parse_enhancedpacketblock_le(&v);
            assert!(res.is_ok());
        }
    }
    #[test]
    fn test_serialize_epb_with_options() {
        let (rem, pkt) =
            parse_block_le(FRAME_PCAPNG_EPB_WITH_OPTIONS).expect("packet creation failed");
        assert!(rem.is_empty());
        if let Block::EnhancedPacket(mut epb) = pkt {
            let v = epb.to_vec().expect("serialize");
            // println!("epb.to_vec: {:?}", v);
            let res = parse_enhancedpacketblock_le(&v);
            assert!(res.is_ok());
        }
    }
    #[test]
    fn test_serialize_dsb() {
        let (rem, pkt) = parse_block_le(FRAME_PCAPNG_DSB).expect("packet creation failed");
        assert!(rem.is_empty());
        assert!(pkt.magic() == DSB_MAGIC);
        if let Block::DecryptionSecrets(mut dsb) = pkt {
            let v = dsb.to_vec().expect("serialize");
            // println!("dsb.to_vec: {:?}", v);
            let res = parse_decryptionsecretsblock_le(&v);
            assert!(res.is_ok());
        }
    }
}
