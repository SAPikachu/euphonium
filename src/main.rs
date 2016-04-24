#![feature(plugin)]
#![plugin(clippy)]

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
mod query;

#[cfg(test)]
mod tests;

use std::net::{SocketAddr, SocketAddrV4};
use std::cmp::max;

use mioco::JoinHandle;
use mioco::udp::UdpSocket;
use mioco::tcp::{TcpListener};
use mioco::mio::Ipv4Addr;
use mioco::sync::mpsc::{channel};
use trust_dns::op::{Message, ResponseCode, Edns, OpCode};
use trust_dns::rr::DNSClass;

use utils::{Result, Error, CloneExt, MessageExt, WithTimeout};
use transport::{DnsTransport};
use query::{query_multiple, EDNS_VER, QUERY_TIMEOUT};

// Idea: Use DNSSEC to check whether a domain is poisoned by GFW

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
    if msg.get_queries().len() != 1 || msg.get_op_code() != OpCode::Query {
        // For simplicity, only support one question
        ret.response_code(ResponseCode::Refused);
        return ret.to_bytes();
    }
    if msg.get_queries()[0].get_query_class() != DNSClass::IN {
        ret.response_code(ResponseCode::NotImp);
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
#[allow(similar_names)]
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

fn mioco_config_start<F, T>(f: F) -> std::thread::Result<T>
    where F: FnOnce() -> T,
          F: Send + 'static,
          T: Send + 'static
{
    let mut config = mioco::Config::new();
    config.set_catch_panics(false);
    mioco::Mioco::new_configured(config).start(f)
}
fn main() {
    env_logger::init().expect("What the ...?");
    println!("Hello, world!");

    mioco_config_start(move || {
        let ip = Ipv4Addr::new(0, 0, 0, 0);
        let port = 5354;
        let addr = SocketAddr::V4(SocketAddrV4::new(ip, port));

        serve_tcp(&addr).expect("Failed to initialize TCP listener");
        serve_udp(&addr).expect("Failed to initialize UDP listener");
    }).expect("Unexpected error from mioco::start");
}
