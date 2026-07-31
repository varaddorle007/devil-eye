//! DNS metadata decoder (query / response summaries).

use simple_dns::{Packet, PacketFlag, RCODE};

use crate::packet::DnsInfo;

/// Decode a DNS message payload into a bounded summary.
pub fn decode_dns(payload: &[u8]) -> Option<DnsInfo> {
    if payload.len() < 12 {
        return None;
    }
    let packet = Packet::parse(payload).ok()?;

    let questions: Vec<String> = packet
        .questions
        .iter()
        .take(8)
        .map(|q| {
            let name = q.qname.to_string();
            let qtype = format!("{:?}", q.qtype);
            format!("{name} {qtype}")
        })
        .collect();

    let answers: Vec<String> = packet
        .answers
        .iter()
        .take(8)
        .map(|a| {
            let name = a.name.to_string();
            let data = format!("{:?}", a.rdata);
            let short = if data.len() > 80 {
                format!("{}…", &data[..77])
            } else {
                data
            };
            format!("{name} {short}")
        })
        .collect();

    let rcode = match packet.rcode() {
        RCODE::NoError => Some(0),
        RCODE::FormatError => Some(1),
        RCODE::ServerFailure => Some(2),
        RCODE::NameError => Some(3),
        RCODE::NotImplemented => Some(4),
        RCODE::Refused => Some(5),
        other => Some(other as u16),
    };

    Some(DnsInfo {
        is_query: !packet.has_flags(PacketFlag::RESPONSE),
        id: packet.id(),
        questions,
        answers,
        rcode,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use simple_dns::{
        rdata::{RData, A},
        Name, Question, ResourceRecord, CLASS, QCLASS, TYPE,
    };

    #[test]
    fn parses_query() {
        let mut packet = Packet::new_query(0x1234);
        packet.questions.push(Question::new(
            Name::new_unchecked("example.com"),
            TYPE::A.into(),
            QCLASS::CLASS(CLASS::IN),
            false,
        ));
        let bytes = packet.build_bytes_vec().unwrap();
        let info = decode_dns(&bytes).expect("dns");
        assert!(info.is_query);
        assert_eq!(info.id, 0x1234);
        assert!(!info.questions.is_empty());
    }

    #[test]
    fn parses_response() {
        let mut packet = Packet::new_reply(1);
        packet.questions.push(Question::new(
            Name::new_unchecked("example.com"),
            TYPE::A.into(),
            QCLASS::CLASS(CLASS::IN),
            false,
        ));
        packet.answers.push(ResourceRecord::new(
            Name::new_unchecked("example.com"),
            CLASS::IN,
            60,
            RData::A(A {
                address: 0x0808_0808,
            }),
        ));
        let bytes = packet.build_bytes_vec().unwrap();
        let info = decode_dns(&bytes).expect("dns");
        assert!(!info.is_query);
        assert!(!info.answers.is_empty());
    }

    #[test]
    fn rejects_short() {
        assert!(decode_dns(&[0u8; 8]).is_none());
    }
}
