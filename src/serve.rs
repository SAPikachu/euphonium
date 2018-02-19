use std::net::{SocketAddr};
use std::cmp::max;

use mioco;
use mioco::JoinHandle;
use mioco::udp::UdpSocket;
use mioco::tcp::{TcpListener};
use mioco::sync::mpsc::{channel};
use trust_dns::op::{Message, ResponseCode, Edns, OpCode};
use trust_dns::rr::{DNSClass, RecordType};
use trust_dns_proto::rr::dnssec::rdata::DNSSECRecordType;
use trust_dns_proto::serialize::binary::BinEncodable;

use utils::{Result, Error, MessageExt, WithTimeout};
use transport::{DnsTransport};
use query::{EDNS_VER};
use resolver::{RcResolver};

/// This function should never fail, otherwise we have a panic
fn handle_request(resolver: &RcResolver, msg: &Message, should_truncate: bool) -> Result<Vec<u8>> {
    let mut ret : Message = msg.new_resp();
    ret.set_recursion_available(true);
    let mut have_dnssec = false;
    if let Some(req_edns) = msg.edns() {
        let mut resp_edns = Edns::new();
        resp_edns.set_version(EDNS_VER);
        have_dnssec = req_edns.dnssec_ok();
        resp_edns.set_dnssec_ok(have_dnssec);
        resp_edns.set_max_payload(max(512, req_edns.max_payload()));
        ret.set_edns(resp_edns);
        if req_edns.version() > EDNS_VER {
            warn!("Got EDNS version {}", req_edns.version());
            ret.set_response_code(ResponseCode::BADVERS);
            return ret.to_bytes().map_err(|e| e.into());
        }
    }
    if msg.queries().len() != 1 || msg.op_code() != OpCode::Query {
        // For simplicity, only support one question
        warn!("Refuse to serve: {:?}", msg);
        ret.set_response_code(ResponseCode::Refused);
        return ret.to_bytes().map_err(|e| e.into());
    }
    if msg.queries()[0].query_class() != DNSClass::IN {
        ret.set_response_code(ResponseCode::NotImp);
        return ret.to_bytes().map_err(|e| e.into());
    }
    match resolver.resolve(&mut ret) {
        Ok(_) => { /* Message is filled with answers */ },
        Err(e) => {
            warn!("Resolver returned error: {:?}", e);
            ret.set_response_code(ResponseCode::ServFail);
        },
    };
    if !have_dnssec {
        ret = ret.strip_dnssec_records();
    } else {
        let is_authenticated = ret.answers().iter()
        .chain(ret.name_servers())
        .any(|rec| rec.rr_type() == RecordType::DNSSEC(DNSSECRecordType::RRSIG));
        ret.set_authentic_data(is_authenticated);
    }
    let mut bytes = try!(ret.to_bytes());
    if should_truncate && bytes.len() > (msg.max_payload() as usize) {
        ret.set_truncated(true);
        ret.take_name_servers();
        ret.take_additionals();
        bytes = ret.to_bytes()?;
        while bytes.len() > (msg.max_payload() as usize) {
            let mut answers = ret.take_answers();
            let new_len = answers.len() / 2;
            answers.truncate(new_len);
            ret.insert_answers(answers);
            bytes = ret.to_bytes()?;
        }
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
        let mut resolver = resolver;
        loop {
            let (msg, addr) = match recv.recv_msg(None) {
                Ok(x) => x,
                Err(e) => {
                    on_error(e);
                    return;
                },
            };
            let sch_req = sch.clone();
            resolver = resolver.sync_config();
            let res = resolver.clone();
            mioco::spawn(move || {
                let resp = handle_request(&res, &msg, TSend::should_truncate()).expect("handle_request should not return error");
                sch_req.send((resp, addr)).expect("Result pipe should not break here");
            });
        }
    })
}
pub fn serve_tcp(addr: &SocketAddr, resolver: RcResolver) -> Result<JoinHandle<()>> {
    let listener = try!(TcpListener::bind(addr));
    Ok(mioco::spawn(move || {
        let mut resolver = resolver;
        loop {
            let sock = listener.accept().expect("Failed to accept TCP socket");
            sock.set_nodelay(true).unwrap_or(());
            let sock_clone = sock.try_clone().expect("Failed to clone TCP socket");
            resolver = resolver.sync_config();
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
        sock, sock_clone, resolver, |e| {
            match e {
                Error::Proto(reason) => warn!("Invalid DNS request: {:?}", reason),
                e2 => panic!("UDP listener is broken: {:?}", e2),
            }
        }
    ))
}
