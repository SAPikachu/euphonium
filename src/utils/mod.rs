use std;
use std::convert::From;
use std::io;

use std::net::SocketAddr;

use itertools::Itertools;
use mioco::udp::UdpSocket;
use trust_dns_client::rr::RData;
use trust_dns_proto::error::ProtoError;
use trust_dns_proto::op::{Message, MessageType, Query};
use trust_dns_proto::rr::{Name, Record, RecordType};
use trust_dns_proto::serialize::binary::BinDecodable;

use crate::query::ErrorKind as QueryErrorKind;
use crate::resolver::ErrorKind as ResolverErrorKind;

pub mod as_disp;
pub mod future;
pub mod ipset;
pub mod jsonrpc;
pub mod with_timeout;
pub use self::as_disp::AsDisplay;
pub use self::future::Future;
pub use self::ipset::IpSet;
pub use self::jsonrpc::{JsonRpcRequest, JsonRpcResponse};
pub use self::with_timeout::WithTimeout;

lazy_static! {
    pub static ref ROOT_NAME: Name = Name::root();
}

quick_error! {
    #[derive(Debug)]
    pub enum Error {
        Io(err: io::Error) {
            from()
            from(kind: io::ErrorKind) -> (io::Error::new(kind, "Io"))
            description(err.description())
            display("{}", err)
        }
        Proto(err: ProtoError) {
            from()
            description(err.description())
            display("{}", err)
        }
        ChannelRecv(err: std::sync::mpsc::RecvError) {
            from()
            description(err.description())
        }
        Resolver(kind: ResolverErrorKind) {
            from()
        }
        Query(kind: QueryErrorKind) {
            from()
        }
        Other(msg: &'static str, extra: Option<String>) {
            description(msg)
            display("{}: {}", msg, extra.as_ref().unwrap_or(&String::new()))
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

pub trait MessageExt {
    fn from_udp(sock: &mut UdpSocket) -> Result<(Message, SocketAddr)>;
    fn strip_dnssec_records(&self) -> Message;
    fn new_resp(&self) -> Message;
    fn clone_resp(&self) -> Message;
    fn clone_resp_for(&self, q: &Query) -> Message;
    fn copy_resp_from(&mut self, other: &Message);
    fn copy_resp_with<F>(&mut self, other: &Message, f: F)
    where
        F: FnMut(&Record) -> Record;
    fn without_rr(&self) -> Message;
    fn is_resp_for(&self, other: &Message) -> bool;
    fn is_cname_chain_complete(&self) -> bool;
}
impl MessageExt for Message {
    fn from_udp(sock: &mut UdpSocket) -> Result<(Message, SocketAddr)> {
        let mut buf = [0u8; 1024 * 16];
        let (l, addr) = (sock.recv(&mut buf))?;
        let msg = (Message::from_bytes(&buf[0..l]))?;
        Ok((msg, addr))
    }
    fn strip_dnssec_records(&self) -> Message {
        let mut filtered = self.without_rr();
        const REMOVED_TYPES: [RecordType; 1] = [RecordType::OPT];
        let query_type = self.queries()[0].query_type();
        let f = |r: &&Record| -> bool {
            let t = r.rr_type();
            if t == query_type {
                return true;
            }
            if let RecordType::DNSSEC(_) = t {
                return false;
            }
            !REMOVED_TYPES.contains(&t)
        };
        self.answers().iter().filter(&f).for_each(|r| {
            filtered.add_answer(r.clone());
        });
        self.name_servers().iter().filter(&f).for_each(|r| {
            filtered.add_name_server(r.clone());
        });
        self.additionals().iter().filter(&f).for_each(|r| {
            filtered.add_additional(r.clone());
        });
        filtered
    }
    fn new_resp(&self) -> Message {
        let mut ret: Message = Message::new();
        ret.set_message_type(MessageType::Response);
        ret.set_id(self.id());
        ret.set_op_code(self.op_code());
        ret.set_recursion_desired(self.recursion_desired());
        for q in self.queries() {
            ret.add_query(q.clone());
        }
        ret
    }
    fn clone_resp(&self) -> Message {
        let mut ret = Message::new();
        ret.copy_resp_from(self);
        ret
    }
    fn clone_resp_for(&self, q: &Query) -> Message {
        let mut ret = self.clone_resp();
        ret.add_query(q.clone());
        ret
    }
    fn without_rr(&self) -> Message {
        // Simpler way to clear all answers
        let mut new_msg = self.truncate();
        assert!(new_msg.queries().is_empty());
        assert!(new_msg.answers().is_empty());
        assert!(new_msg.additionals().is_empty());
        new_msg.take_name_servers();
        new_msg.set_truncated(false);
        new_msg.set_checking_disabled(self.checking_disabled());
        new_msg.set_authentic_data(self.authentic_data());
        self.queries().iter().for_each(|q| {
            new_msg.add_query(q.clone());
        });
        new_msg
    }
    fn copy_resp_from(&mut self, other: &Message) {
        self.copy_resp_with(other, Record::clone)
    }
    fn copy_resp_with<F>(&mut self, other: &Message, mut f: F)
    where
        F: FnMut(&Record) -> Record,
    {
        self.set_response_code(other.response_code());
        self.set_message_type(other.message_type());
        other.answers().iter().map(|x| f(x)).for_each(|x| {
            self.add_answer(x);
        });
        other.name_servers().iter().map(|x| f(x)).for_each(|x| {
            self.add_name_server(x);
        });

        // RFC 2671 4.1: OPT should never be cached nor forwarded
        other
            .additionals()
            .iter()
            .filter(|x| x.rr_type() != RecordType::OPT)
            .map(|x| f(x))
            .for_each(|x| {
                self.add_additional(x);
            });
    }
    fn is_resp_for(&self, other: &Message) -> bool {
        assert_eq!(other.message_type(), MessageType::Query);
        if self.message_type() != MessageType::Response {
            return false;
        }
        if other.id() != self.id() {
            return false;
        }
        if other.op_code() != self.op_code() {
            return false;
        }
        assert_eq!(other.queries().len(), 1);
        if self.queries().len() != 1 {
            return false;
        }
        if other.queries()[0] != self.queries()[0] {
            return false;
        }
        true
    }
    fn is_cname_chain_complete(&self) -> bool {
        assert_eq!(self.message_type(), MessageType::Response);
        assert_eq!(self.queries().len(), 1);
        let query = &self.queries()[0];
        let mut cur_record = self
            .answers()
            .iter()
            .find(|x| x.name() == query.name() && x.record_type() == RecordType::CNAME);
        if cur_record.is_none() {
            // No CNAME in response
            return true;
        }
        let mut checked_names = Vec::<&Name>::new();
        checked_names.push(query.name());
        while let Some(rec) = cur_record {
            if let RData::CNAME(next_name) = rec.rdata() {
                if checked_names.contains(&next_name) {
                    break;
                }
                checked_names.push(next_name);
                let next_recs = self
                    .answers()
                    .iter()
                    .filter(|x| x.name() == next_name)
                    .collect_vec();
                if next_recs.is_empty() {
                    break;
                }
                if next_recs
                    .iter()
                    .any(|x| x.record_type() == query.query_type())
                {
                    return true;
                }
                cur_record = next_recs
                    .iter()
                    .find(|x| x.record_type() == RecordType::CNAME)
                    .map(|x| *x);
            } else {
                panic!("Not CNAME??")
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trust_dns_client::{op::ResponseCode, rr::DNSClass};

    #[test]
    fn test_is_cname_chain_complete() {
        let mut msg = Message::new();
        msg.set_message_type(MessageType::Response);
        let mut query = Query::new();
        query.set_name("a.example.com".parse().unwrap());
        query.set_query_class(DNSClass::IN);
        query.set_query_type(RecordType::A);
        msg.queries_mut().push(query);
        msg.set_response_code(ResponseCode::NoError);

        assert!(msg.is_cname_chain_complete());

        msg.answers_mut().push(Record::from_rdata(
            "a.example.com".parse().unwrap(),
            5,
            RData::A("1.1.1.1".parse().unwrap()),
        ));
        assert!(msg.is_cname_chain_complete());

        // Don't care if there is no CNAME
        msg.take_answers();
        msg.answers_mut().push(Record::from_rdata(
            "a.example.com".parse().unwrap(),
            5,
            RData::AAAA("fc00::1".parse().unwrap()),
        ));
        assert!(msg.is_cname_chain_complete());

        msg.take_answers();
        msg.answers_mut().push(Record::from_rdata(
            "b.example.com".parse().unwrap(),
            5,
            RData::A("1.1.1.1".parse().unwrap()),
        ));
        assert!(msg.is_cname_chain_complete());

        msg.take_answers();
        msg.answers_mut().push(Record::from_rdata(
            "a.example.com".parse().unwrap(),
            5,
            RData::CNAME("b.example.com".parse().unwrap()),
        ));
        msg.answers_mut().push(Record::from_rdata(
            "b.example.com".parse().unwrap(),
            5,
            RData::A("1.1.1.1".parse().unwrap()),
        ));
        assert!(msg.is_cname_chain_complete());

        msg.take_answers();
        msg.answers_mut().push(Record::from_rdata(
            "a.example.com".parse().unwrap(),
            5,
            RData::CNAME("b.example.com".parse().unwrap()),
        ));
        msg.answers_mut().push(Record::from_rdata(
            "b.example.com".parse().unwrap(),
            5,
            RData::CNAME("c.example.com".parse().unwrap()),
        ));
        msg.answers_mut().push(Record::from_rdata(
            "c.example.com".parse().unwrap(),
            5,
            RData::A("1.1.1.1".parse().unwrap()),
        ));
        assert!(msg.is_cname_chain_complete());

        msg.take_answers();
        msg.answers_mut().push(Record::from_rdata(
            "a.example.com".parse().unwrap(),
            5,
            RData::CNAME("b.example.com".parse().unwrap()),
        ));
        msg.answers_mut().push(Record::from_rdata(
            "b.example.com".parse().unwrap(),
            5,
            RData::CNAME("c.example.com".parse().unwrap()),
        ));
        msg.answers_mut().push(Record::from_rdata(
            "c.example.com".parse().unwrap(),
            5,
            RData::A("1.1.1.1".parse().unwrap()),
        ));
        msg.answers_mut().push(Record::from_rdata(
            "c.example.com".parse().unwrap(),
            5,
            RData::A("1.1.1.2".parse().unwrap()),
        ));
        assert!(msg.is_cname_chain_complete());

        msg.take_answers();
        msg.answers_mut().push(Record::from_rdata(
            "a.example.com".parse().unwrap(),
            5,
            RData::CNAME("b.example.com".parse().unwrap()),
        ));
        msg.answers_mut().push(Record::from_rdata(
            "b.example.com".parse().unwrap(),
            5,
            RData::CNAME("c.example.com".parse().unwrap()),
        ));
        msg.answers_mut().push(Record::from_rdata(
            "c.example.com".parse().unwrap(),
            5,
            RData::AAAA("fc00::1".parse().unwrap()),
        ));
        msg.answers_mut().push(Record::from_rdata(
            "c.example.com".parse().unwrap(),
            5,
            RData::A("1.1.1.2".parse().unwrap()),
        ));
        assert!(msg.is_cname_chain_complete());

        msg.take_answers();
        msg.answers_mut().push(Record::from_rdata(
            "a.example.com".parse().unwrap(),
            5,
            RData::CNAME("b.example.com".parse().unwrap()),
        ));
        msg.answers_mut().push(Record::from_rdata(
            "b.example.com".parse().unwrap(),
            5,
            RData::CNAME("c.example.com".parse().unwrap()),
        ));
        msg.answers_mut().push(Record::from_rdata(
            "c.example.com".parse().unwrap(),
            5,
            RData::A("1.1.1.2".parse().unwrap()),
        ));
        msg.answers_mut().push(Record::from_rdata(
            "c.example.com".parse().unwrap(),
            5,
            RData::AAAA("fc00::1".parse().unwrap()),
        ));
        assert!(msg.is_cname_chain_complete());

        // Incomplete chain cases
        msg.take_answers();
        msg.answers_mut().push(Record::from_rdata(
            "a.example.com".parse().unwrap(),
            5,
            RData::CNAME("b.example.com".parse().unwrap()),
        ));
        msg.answers_mut().push(Record::from_rdata(
            "b.example.com".parse().unwrap(),
            5,
            RData::CNAME("c.example.com".parse().unwrap()),
        ));
        msg.answers_mut().push(Record::from_rdata(
            "d.example.com".parse().unwrap(),
            5,
            RData::A("1.1.1.1".parse().unwrap()),
        ));
        assert!(!msg.is_cname_chain_complete());

        msg.take_answers();
        msg.answers_mut().push(Record::from_rdata(
            "a.example.com".parse().unwrap(),
            5,
            RData::CNAME("b.example.com".parse().unwrap()),
        ));
        msg.answers_mut().push(Record::from_rdata(
            "b.example.com".parse().unwrap(),
            5,
            RData::CNAME("c.example.com".parse().unwrap()),
        ));
        msg.answers_mut().push(Record::from_rdata(
            "c.example.com".parse().unwrap(),
            5,
            RData::AAAA("fc00::1".parse().unwrap()),
        ));
        assert!(!msg.is_cname_chain_complete());

        msg.take_answers();
        msg.answers_mut().push(Record::from_rdata(
            "a.example.com".parse().unwrap(),
            5,
            RData::CNAME("b.example.com".parse().unwrap()),
        ));
        msg.answers_mut().push(Record::from_rdata(
            "b.example.com".parse().unwrap(),
            5,
            RData::CNAME("c.example.com".parse().unwrap()),
        ));
        msg.answers_mut().push(Record::from_rdata(
            "c.example.com".parse().unwrap(),
            5,
            RData::CNAME("a.example.com".parse().unwrap()),
        ));
        assert!(!msg.is_cname_chain_complete());

        msg.take_answers();
        msg.answers_mut().push(Record::from_rdata(
            "a.example.com".parse().unwrap(),
            5,
            RData::CNAME("b.example.com".parse().unwrap()),
        ));
        msg.answers_mut().push(Record::from_rdata(
            "b.example.com".parse().unwrap(),
            5,
            RData::CNAME("c.example.com".parse().unwrap()),
        ));
        msg.answers_mut().push(Record::from_rdata(
            "c.example.com".parse().unwrap(),
            5,
            RData::CNAME("b.example.com".parse().unwrap()),
        ));
        assert!(!msg.is_cname_chain_complete());
    }
}
