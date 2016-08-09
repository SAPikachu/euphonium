use std::net::{SocketAddr};
use std::cmp::max;

use mioco;
use mioco::JoinHandle;
use mioco::udp::UdpSocket;
use mioco::tcp::{TcpListener};
use mioco::sync::mpsc::{channel};
use trust_dns::op::{Message, ResponseCode, Edns, OpCode};
use trust_dns::rr::{DNSClass, RecordType, Record};
use itertools::Itertools;

use utils::{Result, Error, MessageExt, WithTimeout};
use transport::{DnsTransport};
use query::{EDNS_VER};
use resolver::{RcResolver};

/// This function should never fail, otherwise we have a panic
fn handle_request(resolver: RcResolver, msg: Message, should_truncate: bool) -> Result<Vec<u8>> {
    let mut ret : Message = msg.new_resp();
    ret.recursion_available(true);
    let mut have_dnssec = false;
    if let Some(req_edns) = msg.get_edns() {
        let mut resp_edns = Edns::new();
        resp_edns.set_version(EDNS_VER);
        have_dnssec = req_edns.is_dnssec_ok();
        resp_edns.set_dnssec_ok(have_dnssec);
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
    match resolver.resolve(&mut ret) {
        Ok(_) => { /* Message is filled with answers */ },
        Err(e) => {
            warn!("Resolver returned error: {:?}", e);
            ret.response_code(ResponseCode::ServFail);
        },
    };
    if !have_dnssec {
        ret = {
            let mut filtered = ret.without_rr();
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
            let query_type = ret.get_queries()[0].get_query_type();
            let f = |r: &&Record| -> bool {
                let t = r.get_rr_type();
                t == query_type || !REMOVED_TYPES.contains(&t)
            };
            ret.get_answers().iter().filter(&f)
            .foreach(|r| { filtered.add_answer(r.clone()); });
            ret.get_name_servers().iter().filter(&f)
            .foreach(|r| { filtered.add_name_server(r.clone()); });
            ret.get_additional().iter().filter(&f)
            .foreach(|r| { filtered.add_additional(r.clone()); });
            filtered
        };
    } else {
        let is_authenticated = ret.get_answers().iter()
        .chain(ret.get_name_servers())
        .any(|rec| rec.get_rr_type() == RecordType::RRSIG);
        ret.authentic_data(is_authenticated);
    }
    let bytes = try!(ret.to_bytes());
    if should_truncate && bytes.len() > (msg.get_max_payload() as usize) {
        return ret.truncate().to_bytes();
    }
    Ok(bytes)
}
#[allow(similar_names)]
fn serve_transport_async<TRecv, TSend, F>(mut recv: TRecv, mut send: TSend, resolver: RcResolver, on_error: F) -> JoinHandle<()>
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
            let res = resolver.clone();
            mioco::spawn(move || {
                let resp = handle_request(res, msg, TSend::should_truncate()).expect("handle_request should not return error");
                sch_req.send((resp, addr)).expect("Result pipe should not break here");
            });
        }
    })
}
pub fn serve_tcp(addr: &SocketAddr, resolver: RcResolver) -> Result<JoinHandle<()>> {
    let listener = try!(TcpListener::bind(addr));
    Ok(mioco::spawn(move || {
        loop {
            let sock = listener.accept().expect("Failed to accept TCP socket");
            sock.set_nodelay(true).unwrap_or(());
            let sock_clone = sock.try_clone().expect("Failed to clone TCP socket");
            serve_transport_async(
                sock.with_resetting_timeout(*resolver.config.serve.tcp_timeout),
                sock_clone.with_resetting_timeout(*resolver.config.serve.tcp_timeout),
                resolver.clone(),
                |e| trace!("Client TCP connection is broken: {:?}", e)
            );
        }
    }))
}
pub fn serve_udp(addr: &SocketAddr, resolver: RcResolver) -> Result<JoinHandle<()>> {
    let sock : UdpSocket = try!(UdpSocket::bound(addr));
    let sock_clone = try!(sock.try_clone());
    Ok(serve_transport_async(
        sock, sock_clone, resolver, |e| panic!("UDP listener is broken: {:?}", e)
    ))
}
