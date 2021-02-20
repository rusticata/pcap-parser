use crate::data::PacketData;
use nom::bytes::streaming::{tag, take};
use nom::multi::many_till;
use nom::number::streaming::be_u16;
use nom::IResult;
use std::convert::TryFrom;

/* values from epan/exported_pdu.h */

pub const EXP_PDU_TAG_PROTO_NAME: u16 = 12;
pub const EXP_PDU_TAG_DISSECTOR_TABLE_NAME: u16 = 14;

pub const EXP_PDU_TAG_DISSECTOR_TABLE_NAME_NUM_VAL: u16 = 32;

#[derive(Debug)]
pub struct ExportedTlv<'a> {
    pub t: u16,
    pub l: u16,
    pub v: &'a [u8],
}

pub fn parse_exported_tlv(i: &[u8]) -> IResult<&[u8], ExportedTlv> {
    let (i, t) = be_u16(i)?;
    let (i, l) = be_u16(i)?;
    let (i, v) = take(l)(i)?;
    Ok((i, ExportedTlv { t, l, v }))
}

pub fn parse_many_exported_tlv(i: &[u8]) -> IResult<&[u8], Vec<ExportedTlv>> {
    many_till(parse_exported_tlv, tag(b"\x00\x00\x00\x00"))(i).map(|(rem, (v, _))| (rem, v))
}

/// Get packet data for WIRESHARK_UPPER_PDU (252)
///
/// Upper-layer protocol saves from Wireshark
pub fn get_packetdata_wireshark_upper_pdu(i: &[u8], caplen: usize) -> Option<PacketData> {
    if i.len() < caplen || caplen == 0 {
        None
    } else {
        match parse_many_exported_tlv(i) {
            Ok((rem, v)) => {
                // get protocol name (or return None)
                let proto_name = v
                    .iter()
                    .find(|tlv| tlv.t == EXP_PDU_TAG_DISSECTOR_TABLE_NAME)
                    .map(|tlv| tlv.v)?;
                // get protocol value (or return None)
                let ip_proto = v
                    .iter()
                    .find(|tlv| tlv.t == EXP_PDU_TAG_DISSECTOR_TABLE_NAME_NUM_VAL && tlv.l >= 4)
                    .map(|tlv| {
                        let int_bytes = <[u8; 4]>::try_from(tlv.v).expect("Convert bytes to u32");
                        u32::from_be_bytes(int_bytes)
                    })?;
                match proto_name {
                    b"ip.proto" => Some(PacketData::L4(ip_proto as u8, rem)),
                    _ => {
                        // XXX unknown protocol name
                        None
                    }
                }
            }
            _ => None,
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::get_packetdata_wireshark_upper_pdu;
    use crate::data::PacketData;
    use hex_literal::hex;
    pub const UPPER_PDU: &[u8] = &hex!(
        "
00 0e 00 08 69 70 2e 70 72 6f 74 6f 00 20 00 04
00 00 00 11 00 00 00 00 00 58 20 20 20 ff ff 20
63 20 68 20 a0 20 7f 20 8a 20 20 20 20 20 20 ff
ff ff ff ff 20 00 00 00"
    );
    #[test]
    fn test_wireshark_exported_pdu() {
        match get_packetdata_wireshark_upper_pdu(UPPER_PDU, UPPER_PDU.len()) {
            Some(PacketData::L4(proto, data)) => {
                assert_eq!(proto, 17);
                assert_eq!(data.len(), 32);
            }
            None => panic!("get_packetdata_wireshark_upper_pdu could not decode exported PDU"),
            _ => panic!("unexpected result type from get_packetdata_wireshark_upper_pdu"),
        }
    }
}
