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

use mioco::JoinHandle;
use mioco::udp::UdpSocket;
use mioco::tcp::{TcpListener, TcpStream};
use mioco::mio::Ipv4Addr;
use mioco::sync::mpsc::{channel};
use trust_dns::op::{Message, MessageType, ResponseCode, Query, OpCode, Edns};

use utils::{Result, Error, CloneExt, MessageExt, WithTimeout, Future};
use utils::with_timeout::TcpStreamExt;
use transport::{DnsTransport, BoundDnsTransport};

const QUERY_TIMEOUT: i64 = 5000;
const EDNS_VER: u8 = 0;
const EDNS_MAX_PAYLOAD: u16 = 1200;

// Idea: Use DNSSEC to check whether a domain is poisoned by GFW

fn query_core<T: DnsTransport>(q: Query, mut transport: BoundDnsTransport<T>, enable_edns: bool) -> Result<Message> {
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
           transport, msg.get_id(), q.get_name(), q.get_query_type(), q.get_query_class());
    msg.add_query(q);
    try!(transport.send_msg(&msg));
    loop {
        let (resp, _) = try!(transport.recv_msg());
        if ! resp.is_resp_for(&msg) {
            warn!("Q[{}][{}] Invalid response: {:?}",
                  transport, msg.get_id(), resp);
            continue;
        }
        if resp.get_response_code() == ResponseCode::FormErr && enable_edns {
            // Maybe the server doesn't implement EDNS?
            return query_core(msg.get_queries()[0].clone(), transport, false);
        }
        // TODO: Validate response, handle truncated message
        debug!("A[{}][{}] {:?} {} answer(s)",
           transport, resp.get_id(), resp.get_response_code(), resp.get_answers().len());
        return Ok(resp);
    }
}
fn query(q: Query, addr: Ipv4Addr, enable_edns: bool) -> Result<Message> {
    let target = SocketAddr::new(IpAddr::V4(addr), 53);
    let mut transport = try!(UdpSocket::v4()).with_timeout(QUERY_TIMEOUT);
    match query_core(q, transport.bound(Some(&target)), enable_edns) {
        Ok(msg) => {
            if msg.is_truncated() {
                // Try TCP
                let tcp_result = TcpStream::connect_with_timeout(&target, QUERY_TIMEOUT)
                .map_err(|e| e.into())
                .and_then(|stream| stream.set_nodelay(true).or(Ok(())).map(|_| stream))
                .and_then(|stream| query_core(
                    msg.get_queries()[0].clone(),
                    stream.with_timeout(QUERY_TIMEOUT).bound(Some(&target)),
                    enable_edns,
                ));
                Ok(tcp_result.unwrap_or(msg))
            } else {
                Ok(msg)
            }
        },
        Err(e) => Err(e),
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

/// This function should never fail, otherwise we have a panic
fn handle_request(msg: Message, should_truncate: bool) -> Result<Vec<u8>> {
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
            return ret.to_bytes();
        }
    }
    if msg.get_queries().len() != 1 {
        // For simplicity, only support one question
        ret.response_code(ResponseCode::Refused);
        return ret.to_bytes();
    }
    match query_multiple(&msg.get_queries()[0], &[Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(8, 8, 4, 4)]) {
        Ok(resp) => { ret.copy_resp_from(&resp); },
        Err(_)   => { ret.response_code(ResponseCode::ServFail); },
    };
    let bytes = try!(ret.to_bytes());
    if should_truncate && bytes.len() > (msg.get_max_payload() as usize) {
        return ret.truncate().to_bytes();
    }
    Ok(bytes)
}
fn serve_transport_async<TRecv, TSend, F>(mut recv: TRecv, mut send: TSend, on_error: F) -> JoinHandle<()>
    where TRecv: DnsTransport + Send + 'static,
          TSend: DnsTransport + Send + 'static,
          F: FnOnce(Error) + Send + 'static,
{
    let (sch, rch) = channel::<(Vec<u8>, Option<SocketAddr>)>();
    mioco::spawn(move || {
        loop {
            match rch.recv() {
                Ok((buf, addr)) => {
                    match send.send_msg_bytes(&buf, addr.as_ref()) {
                        Ok(_) => { },
                        Err(e) => { warn!("Failed to respond to DNS request: {:?}", e); },
                    };
                },
                Err(_) => {
                    trace!("Channel is broken");
                    return;
                },
            };
        }
    });
    mioco::spawn(move || {
        loop {
            let (msg, addr) = match recv.recv_msg(None) {
                Ok(x) => x,
                Err(e) => {
                    on_error(e);
                    return;
                },
            };
            let sch_req = sch.clone();
            mioco::spawn(move || {
                let resp = handle_request(msg, TSend::should_truncate()).expect("handle_request should not return error");
                sch_req.send((resp, addr)).expect("Result pipe should not break here");
            });
        }
    })
}
fn serve_tcp(addr: &SocketAddr) -> Result<JoinHandle<()>> {
    let listener = try!(TcpListener::bind(addr));
    Ok(mioco::spawn(move || {
        loop {
            let sock = listener.accept().expect("Failed to accept TCP socket");
            sock.set_nodelay(true).unwrap_or(());
            let sock_clone = sock.try_clone().expect("Failed to clone TCP socket");
            serve_transport_async(
                sock.with_resetting_timeout(QUERY_TIMEOUT),
                sock_clone.with_resetting_timeout(QUERY_TIMEOUT),
                |e| trace!("Client TCP connection is broken: {:?}", e)
            );
        }
    }))
}
fn serve_udp(addr: &SocketAddr) -> Result<JoinHandle<()>> {
    let sock : UdpSocket = try!(UdpSocket::v4());
    try!(sock.bind(addr));
    let sock_clone = try!(sock.try_clone());
    Ok(serve_transport_async(
        sock, sock_clone, |e| panic!("UDP listener is broken: {:?}", e)
    ))
}

fn main() {
    env_logger::init().unwrap();
    println!("Hello, world!");

    mioco::start(move || {
        let ip = Ipv4Addr::new(0, 0, 0, 0);
        let port = 5354;
        let addr = SocketAddr::V4(SocketAddrV4::new(ip, port));

        serve_tcp(&addr).expect("Failed to initialize TCP listener");
        serve_udp(&addr).expect("Failed to initialize UDP listener");
    }).expect("Unexpected error from mioco::start");
}
