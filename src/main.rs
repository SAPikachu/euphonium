extern crate env_logger;
extern crate mioco;
extern crate trust_dns;
extern crate rand;
#[macro_use] extern crate quick_error;
#[macro_use] extern crate log;

mod future;
mod utils;

use std::net::{SocketAddr, SocketAddrV4, IpAddr};

use mioco::udp::UdpSocket;
use mioco::mio::Ipv4Addr;
use trust_dns::op::{Message, MessageType, ResponseCode, Query, OpCode};

use utils::{Result, CloneExt, MessageExt};
use future::Future;

fn query(q: Query, server: Ipv4Addr) -> Result<Message> {
    let mut msg : Message = Message::new();
    msg.message_type(MessageType::Query);
    msg.id(rand::random());
    msg.op_code(OpCode::Query);
    msg.recursion_desired(true);
    debug!("Q[{}][{}] {} {:?} {:?}",
           server, msg.get_id(), q.get_name(), q.get_query_type(), q.get_query_class());
    msg.add_query(q);
    let msg_data = try!(msg.to_bytes());
    let mut sock = try!(UdpSocket::v4());
    let target = SocketAddr::new(IpAddr::V4(server), 53);
    try!(sock.send(&msg_data, &target));
    loop {
        let (resp, addr) = try!(Message::from_udp(&mut sock));
        if addr != target {
            warn!("Q[{}][{}] Response from unexpected server: {}",
                  server, msg.get_id(), addr);
            continue
        }
        if ! resp.is_resp_for(&msg) {
            warn!("Q[{}][{}] Invalid response: {:?}",
                  server, msg.get_id(), resp);
            continue
        }
        // TODO: Validate response, handle truncated message, retry and timeout
        debug!("A[{}][{}] {} answer(s)",
           server, resp.get_id(), resp.get_answers().len());
        return Ok(resp);
    };
}
fn query_multiple(q: &Query, servers: &[Ipv4Addr]) -> Result<Message> {
    let mut futures = servers.iter()
        .cloned()
        .map(move |server| {
            let qc = q.clone();
            Future::from_fn(move || query(qc, server.clone()))
        })
        .collect::<Vec<Future<Result<Message>>>>();
    let result_index = Future::wait_any(&mut futures);
    futures.remove(result_index).consume()
}

fn handle_request(msg: Message) -> Message {
    let mut ret : Message = msg.new_resp();
    ret.recursion_available(true);
    if msg.get_queries().len() != 1 {
        // For simplicity, only support one question
        ret.response_code(ResponseCode::Refused);
        return ret;
    }
    // TODO: EDNS?
    match query_multiple(&msg.get_queries()[0], &[Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(8, 8, 4, 4)]) {
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
