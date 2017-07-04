use std;
use std::io;
use std::convert::From;

use std::net::SocketAddr;

use mioco::udp::UdpSocket;
use trust_dns::op::{Message, Query, MessageType};
use trust_dns::error::{DecodeError, EncodeError, DnsSecError};
use trust_dns::rr::{RecordType, Record, Name};
use trust_dns::serialize::binary::{BinDecoder, BinEncoder, BinSerializable};
use itertools::Itertools;

use ::resolver::ErrorKind as ResolverErrorKind;
use ::query::ErrorKind as QueryErrorKind;

pub mod future;
pub mod with_timeout;
pub mod as_disp;
pub mod ipset;
pub mod jsonrpc;
pub use self::with_timeout::WithTimeout;
pub use self::future::Future;
pub use self::as_disp::AsDisplay;
pub use self::ipset::IpSet;
pub use self::jsonrpc::{JsonRpcRequest, JsonRpcResponse};

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
        Decode(err: DecodeError) {
            from()
            description(err.description())
        }
        Encode(err: EncodeError) {
            from()
            description(err.description())
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
        Dnssec(err: DnsSecError) {
            from()
            description(err.description())
        }
        Other(msg: &'static str, extra: Option<String>) {
            description(msg)
            display("{}: {}", msg, extra.as_ref().unwrap_or(&String::new()))
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

pub trait MessageExt {
    fn to_bytes(&self) -> Result<Vec<u8>>;
    fn from_bytes(buf: &[u8]) -> Result<Message>;
    fn from_udp(sock: &mut UdpSocket) -> Result<(Message, SocketAddr)>;
    fn strip_dnssec_records(&self) -> Message;
    fn new_resp(&self) -> Message;
    fn clone_resp(&self) -> Message;
    fn clone_resp_for(&self, q: &Query) -> Message;
    fn copy_resp_from(&mut self, other: &Message);
    fn copy_resp_with<F>(&mut self, other: &Message, mut f: F)
        where F: FnMut(&Record) -> Record;
    fn without_rr(&self) -> Message;
    fn is_resp_for(&self, other: &Message) -> bool;
}
impl MessageExt for Message {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut ret = Vec::<u8>::new();
        {
            let mut encoder = BinEncoder::new(&mut ret);
            try!(self.emit(&mut encoder));
        }
        Ok(ret)
    }
    fn from_bytes(buf: &[u8]) -> Result<Message> {
        let mut decoder = BinDecoder::new(buf);
        let msg = try!(Message::read(&mut decoder));
        Ok(msg)
    }
    fn from_udp(sock: &mut UdpSocket) -> Result<(Message, SocketAddr)> {
        let mut buf = [0u8; 1024 * 16];
        let (l, addr) = try!(sock.recv(&mut buf));
        let msg = try!(Message::from_bytes(&buf[0..l]));
        Ok((msg, addr))
    }
    fn strip_dnssec_records(&self) -> Message {
        let mut filtered = self.without_rr();
        const REMOVED_TYPES: [RecordType; 8] = [
            RecordType::RRSIG,
            RecordType::NSEC,
            RecordType::NSEC3,
            RecordType::DS,
            RecordType::DNSKEY,
            RecordType::KEY,
            RecordType::NSEC3PARAM,
            RecordType::OPT,
        ];
        let query_type = self.queries()[0].query_type();
        let f = |r: &&Record| -> bool {
            let t = r.rr_type();
            t == query_type || !REMOVED_TYPES.contains(&t)
        };
        self.answers().iter().filter(&f)
        .foreach(|r| { filtered.add_answer(r.clone()); });
        self.name_servers().iter().filter(&f)
        .foreach(|r| { filtered.add_name_server(r.clone()); });
        self.additionals().iter().filter(&f)
        .foreach(|r| { filtered.add_additional(r.clone()); });
        filtered
    }
    fn new_resp(&self) -> Message {
        let mut ret : Message = Message::new();
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
        assert!(new_msg.name_servers().is_empty());
        assert!(new_msg.additionals().is_empty());
        new_msg.set_truncated(false);
        new_msg.set_checking_disabled(self.checking_disabled());
        new_msg.set_authentic_data(self.authentic_data());
        self.queries().iter().foreach(|q| { new_msg.add_query(q.clone()); });
        new_msg
    }
    fn copy_resp_from(&mut self, other: &Message) {
        self.copy_resp_with(other, Record::clone)
    }
    fn copy_resp_with<F>(&mut self, other: &Message, mut f: F)
        where F: FnMut(&Record) -> Record,
    {
        self.set_response_code(other.response_code());
        self.set_message_type(other.message_type());
        other.answers().iter()
        .map(|x| f(x))
        .foreach(|x| { self.add_answer(x); });
        other.name_servers().iter()
        .map(|x| f(x))
        .foreach(|x| { self.add_name_server(x); });

        // RFC 2671 4.1: OPT should never be cached nor forwarded
        other.additionals().iter()
        .filter(|x| x.rr_type() != RecordType::OPT)
        .map(|x| f(x))
        .foreach(|x| { self.add_additional(x); });
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
}
