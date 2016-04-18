extern crate env_logger;
extern crate mioco;
extern crate trust_dns;
extern crate rand;
#[macro_use] extern crate quick_error;
#[macro_use] extern crate log;

mod utils;

use std::net::{SocketAddr, SocketAddrV4, IpAddr};

use mioco::udp::UdpSocket;
use mioco::mio::Ipv4Addr;
use trust_dns::rr::domain;
use trust_dns::rr::{DNSClass, RecordType, Record, RData};
use trust_dns::op::{Message, MessageType, ResponseCode, Query, OpCode};
use trust_dns::serialize::binary::{BinDecoder, BinEncoder, BinSerializable};

use utils::{Result, CloneExt, MessageExt};

fn query(q: Query, server: Ipv4Addr) -> Result<Message> {
    debug!("Q[{}][{}] {:?} {:?}",
           server, q.get_name(), q.get_query_type(), q.get_query_class());
    let mut msg : Message = Message::new();
    msg.message_type(MessageType::Query);
    msg.id(rand::random());
    msg.op_code(OpCode::Query);
    msg.recursion_desired(true);
    msg.add_query(q);
    let msg_data = try!(msg.to_bytes());
    let mut sock = try!(UdpSocket::v4());
    let target = SocketAddr::new(IpAddr::V4(server), 53);
    try!(sock.send(&msg_data, &target));
    loop {
        let (resp, addr) = try!(Message::from_udp(&mut sock));
        if addr != target {
            warn!("Q[{}][{}] Response from unexpected server: {}",
                  server, msg.get_queries()[0].get_name(), addr);
            continue
        }
        if ! resp.is_resp_for(&msg) {
            warn!("Q[{}][{}] Invalid response: {:?}",
                  server, msg.get_queries()[0].get_name(), resp);
            continue
        }
        // TODO: Validate response, retry and timeout
        return Ok(resp);
    };
}

fn handle_request(msg: Message) -> Message {
    let mut ret : Message = msg.new_resp();
    ret.recursion_available(true);
    if msg.get_queries().len() != 1 {
        // For simplicity, only support one questionreturn 
        ret.response_code(ResponseCode::Refused);
        return ret;
    }
    // TODO: EDNS?
    match query(msg.get_queries()[0].clone(), Ipv4Addr::new(8, 8, 8, 8)) {
        Ok(resp) => { ret.copy_resp_from(&resp); },
        Err(_)   => { ret.response_code(ResponseCode::ServFail); },
    };
    ret
}

fn main() {
    env_logger::init().unwrap();
    println!("Hello, world!");

    mioco::start(move || {
        let ip = Ipv4Addr::new(0, 0, 0, 0);
        let port = 5354;
        let addr = SocketAddr::V4(SocketAddrV4::new(ip, port));

        mioco::spawn(move || -> Result<()> {
            let mut sock : UdpSocket = UdpSocket::v4().unwrap();
            sock.bind(&addr).unwrap();

            loop {
                let (msg, addr) = try!(Message::from_udp(&mut sock));
                let ret = handle_request(msg);
                let resp = try!(ret.to_bytes());
                try!(sock.send(&resp, &addr));
            }
        });
    }).unwrap();
}
