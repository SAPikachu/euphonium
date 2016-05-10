use std;
use std::io;
use std::convert::From;

use std::net::SocketAddr;

use mioco::udp::UdpSocket;
use trust_dns::op::{Message, Query, MessageType};
use trust_dns::error::{DecodeError, EncodeError};
use trust_dns::rr::{RecordType, Record};
use trust_dns::serialize::binary::{BinDecoder, BinEncoder, BinSerializable};
use itertools::Itertools;

use ::resolver::ErrorKind as ResolverErrorKind;

pub mod future;
pub mod with_timeout;
pub mod as_disp;
pub use self::with_timeout::WithTimeout;
pub use self::future::Future;
pub use self::as_disp::AsDisplay;

quick_error! {
    #[derive(Debug)]
    pub enum Error {
        Io(err: io::Error) {
            from()
            from(kind: io::ErrorKind) -> (io::Error::new(kind, "Io"))
            description(err.description())
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
        ResolverError(kind: ResolverErrorKind) {
            from()
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

pub trait CloneExt {
    fn clone(&self) -> Self;
}

impl CloneExt for Query {
    fn clone(&self) -> Query {
        let mut ret = Query::new();
        ret.name(self.get_name().clone())
            .query_type(self.get_query_type())
            .query_class(self.get_query_class());
        ret
    }
}

pub trait MessageExt {
    fn to_bytes(&self) -> Result<Vec<u8>>;
    fn from_bytes(buf: &[u8]) -> Result<Message>;
    fn from_udp(sock: &mut UdpSocket) -> Result<(Message, SocketAddr)>;
    fn new_resp(&self) -> Message;
    fn clone_resp(&self) -> Message;
    fn clone_resp_for(&self, q: &Query) -> Message;
    fn copy_resp_from(&mut self, other: &Message);
    fn copy_resp_with<F>(&mut self, other: &Message, mut f: F)
        where F: FnMut(&Record) -> Record;
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
    fn new_resp(&self) -> Message {
        let mut ret : Message = Message::new();
        ret.message_type(MessageType::Response);
        ret.id(self.get_id());
        ret.op_code(self.get_op_code());
        ret.recursion_desired(self.is_recursion_desired());
        for q in self.get_queries() {
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
    fn copy_resp_from(&mut self, other: &Message) {
        self.copy_resp_with(other, Record::clone)
    }
    fn copy_resp_with<F>(&mut self, other: &Message, mut f: F)
        where F: FnMut(&Record) -> Record,
    {
        self.response_code(other.get_response_code());
        other.get_answers().iter()
        .map(|x| f(x))
        .foreach(|x| { self.add_answer(x); });
        other.get_name_servers().iter()
        .map(|x| f(x))
        .foreach(|x| { self.add_name_server(x); });

        // RFC 2671 4.1: OPT should never be cached nor forwarded
        other.get_additional().iter()
        .filter(|x| x.get_rr_type() != RecordType::OPT)
        .map(|x| f(x))
        .foreach(|x| { self.add_additional(x); });
    }
    fn is_resp_for(&self, other: &Message) -> bool {
        assert_eq!(other.get_message_type(), MessageType::Query);
        if self.get_message_type() != MessageType::Response {
            return false;
        }
        if other.get_id() != self.get_id() {
            return false;
        }
        if other.get_op_code() != self.get_op_code() {
            return false;
        }
        assert_eq!(other.get_queries().len(), 1);
        if self.get_queries().len() != 1 {
            return false;
        }
        if other.get_queries()[0] != self.get_queries()[0] {
            return false;
        }
        true
    }
}
