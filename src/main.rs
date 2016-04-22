extern crate env_logger;
extern crate mio;
#[macro_use] extern crate mioco;
extern crate trust_dns;
extern crate rand;
#[macro_use] extern crate quick_error;
#[macro_use] extern crate log;
extern crate byteorder;

mod utils;
mod transport;

use std::net::{SocketAddr, SocketAddrV4, IpAddr};
use std::cmp::max;

use mioco::udp::UdpSocket;
use mioco::tcp::TcpListener;
use mioco::mio::Ipv4Addr;
use mioco::sync::mpsc::{Sender, channel};
use trust_dns::op::{Message, MessageType, ResponseCode, Query, OpCode, Edns};

use utils::{Result, Error, CloneExt, MessageExt, WithTimeout, Future};
use transport::DnsTransport;

const QUERY_TIMEOUT: i64 = 5000;
const EDNS_VER: u8 = 0;
const EDNS_MAX_PAYLOAD: u16 = 1200;

// Idea: Use DNSSEC to check whether a domain is poisoned by GFW

fn query(q: Query, server: Ipv4Addr, enable_edns: bool) -> Result<Message> {
    let mut msg : Message = Message::new();
    msg.message_type(MessageType::Query);
    msg.id(rand::random());
    msg.op_code(OpCode::Query);
    msg.recursion_desired(true);
    if enable_edns {
        let mut edns = Edns::new();
        edns.set_version(EDNS_VER);
        edns.set_dnssec_ok(false); // TODO
        edns.set_max_payload(EDNS_MAX_PAYLOAD);
        msg.set_edns(edns);
    }
    debug!("Q[{}][{}] {} {:?} {:?}",
           server, msg.get_id(), q.get_name(), q.get_query_type(), q.get_query_class());
    msg.add_query(q);
    let msg_data = try!(msg.to_bytes());
    let mut sock = try!(UdpSocket::v4());
    let target = SocketAddr::new(IpAddr::V4(server), 53);
    try!(sock.send(&msg_data, &target));
    let mut buf = [0u8; 1024 * 16];
    loop {
        let (len, addr) = try!(sock.with_timeout(QUERY_TIMEOUT).recv(&mut buf));
        if addr != target {
            warn!("Q[{}][{}] Response from unexpected server: {}",
                  server, msg.get_id(), addr);
            continue
        }
        let resp = try!(Message::from_bytes(&buf[0..len]));
        if ! resp.is_resp_for(&msg) {
            warn!("Q[{}][{}] Invalid response: {:?}",
                  server, msg.get_id(), resp);
            continue
        }
        if resp.get_response_code() == ResponseCode::FormErr && enable_edns {
            // Maybe the server doesn't implement EDNS?
            return query(msg.get_queries()[0].clone(), server, false);
        }
        // TODO: Validate response, handle truncated message
        debug!("A[{}][{}] {:?} {} answer(s)",
           server, resp.get_id(), resp.get_response_code(), resp.get_answers().len());
        return Ok(resp);
    }
}
fn query_multiple(q: &Query, servers: &[Ipv4Addr]) -> Result<Message> {
    let mut futures = servers.iter()
        .cloned()
        .map(move |server| {
            let qc = q.clone();
            Future::from_fn(move || query(qc, server, true))
        })
        .collect::<Vec<Future<Result<Message>>>>();
    loop {
        let result_index = Future::wait_any(&mut futures);
        let result = futures.remove(result_index).consume();
        let mut should_return = futures.len() == 0;
        match result {
            Ok(ref msg) => {
                match msg.get_response_code() {
                    ResponseCode::ServFail |
                    ResponseCode::NotImp |
                    ResponseCode::Refused => {
                        // Fall below to wait for remaining servers, if any
                    },
                    _ => { should_return = true; },
                }
            },
            Err(Error::Io(ref err)) if err.kind() == std::io::ErrorKind::TimedOut => {
                debug!("{:?} timed out", q);
            },
            Err(ref err) => {
                debug!("{:?} returned error {:?}", q, err);
            },
        };
        if should_return {
            return result;
        }
    }
}

fn handle_request(msg: Message, should_truncate: bool) -> Vec<u8> {
    let mut ret : Message = msg.new_resp();
    ret.recursion_available(true);
    if let Some(req_edns) = msg.get_edns() {
        let mut resp_edns = Edns::new();
        resp_edns.set_version(EDNS_VER);
        resp_edns.set_dnssec_ok(false); // TODO
        resp_edns.set_max_payload(max(512, req_edns.get_max_payload()));
        ret.set_edns(resp_edns);
        if req_edns.get_version() > EDNS_VER {
            warn!("Got EDNS version {}", req_edns.get_version());
            ret.response_code(ResponseCode::BADVERS);
            return ret.to_bytes().unwrap();
        }
    }
    if msg.get_queries().len() != 1 {
        // For simplicity, only support one question
        ret.response_code(ResponseCode::Refused);
        return ret.to_bytes().unwrap();
    }
    match query_multiple(&msg.get_queries()[0], &[Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(8, 8, 4, 4)]) {
        Ok(resp) => { ret.copy_resp_from(&resp); },
        Err(_)   => { ret.response_code(ResponseCode::ServFail); },
    };
    let bytes = ret.to_bytes().unwrap();
    if should_truncate && bytes.len() > (msg.get_max_payload() as usize) {
        return ret.truncate().to_bytes().unwrap();
    }
    bytes
}
fn handle_request_async(msg: Message, addr: SocketAddr, sender: Sender<(Vec<u8>, SocketAddr)>) {
    mioco::spawn(move || {
        sender.send((handle_request(msg, true), addr)).unwrap();
    });
}
fn handle_one_request<T: DnsTransport>(sock: &mut T) -> Result<()> {
    let (msg, addr) = try!(sock.recv_msg(None));
    let resp = handle_request(msg, T::should_truncate());
    sock.send_msg_bytes(&resp, addr.as_ref()).map_err(|x| x.into())
}
fn serve_tcp(addr: SocketAddr) -> Result<()> {
    let listener = try!(TcpListener::bind(&addr));
    mioco::spawn(move || {
        loop {
            let mut sock = listener.accept().unwrap();
            mioco::spawn(move || {
                loop {
                    match handle_one_request(&mut sock.with_timeout(QUERY_TIMEOUT * 2)) {
                        Ok(_) => { continue; },
                        Err(Error::Io(e)) => {
                            // IO error is usually caused by client disconnecting
                            trace!("IO error while handling TCP request: {:?}", e);
                        },
                        Err(e) => {
                            warn!("Error while handling TCP request: {:?}", e);
                        },
                    };
                    return;
                }
            });
        }
    });
    Ok(())
}

fn main() {
    env_logger::init().unwrap();
    println!("Hello, world!");

    mioco::start(move || {
        let ip = Ipv4Addr::new(0, 0, 0, 0);
        let port = 5354;
        let addr = SocketAddr::V4(SocketAddrV4::new(ip, port));

        mioco::spawn(move || -> Result<()> {
            serve_tcp(addr.clone()).expect("Failed to create TCP listener");
            let mut sock : UdpSocket = UdpSocket::v4().expect("Failed to create UDP socket");
            sock.bind(&addr).expect("Failed to bind UDP socket");

            let (sender, receiver) = channel::<(Vec<u8>, SocketAddr)>();
            {
                let mut sock_resp = sock.try_clone().unwrap();
                mioco::spawn(move || {
                    loop {
                        let (bytes, addr) = receiver.recv().unwrap();
                        match sock_resp.send(&bytes, &addr) {
                            Ok(_) => {},
                            Err(x) => warn!("Fail to send reply to {}: {:?}", addr, x),
                        };
                    }
                });
            }

            loop {
                let (msg, addr) = try!(Message::from_udp(&mut sock));
                handle_request_async(msg, addr, sender.clone());
            }
        })
        .join()
        .expect("Unexpected error from main loop")
        .expect("Unexpected error return from main loop");
    }).expect("Unexpected error from mioco::start");
}
