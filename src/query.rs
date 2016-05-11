use std::net::{SocketAddr, IpAddr};
use std::io;

use rand;
use mioco::udp::UdpSocket;
use mioco::tcp::{TcpStream};
use trust_dns::op::{Message, MessageType, ResponseCode, Query, OpCode, Edns};

use utils::{Result, Error, CloneExt, MessageExt, WithTimeout, Future};
use utils::with_timeout::TcpStreamExt;
use transport::{DnsTransport, BoundDnsTransport};

pub const QUERY_TIMEOUT: i64 = 5000;
pub const EDNS_VER: u8 = 0;
pub const EDNS_MAX_PAYLOAD: u16 = 1200;

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
        debug!("A[{}][{}] {:?} {}/{}/{}",
           transport,
           resp.get_id(),
           resp.get_response_code(),
           resp.get_answers().len(),
           resp.get_name_servers().len(),
           resp.get_additional().len(),
        );
        return Ok(resp);
    }
}
fn get_bind_addr(target: &IpAddr) -> SocketAddr {
    SocketAddr::new(match *target {
        IpAddr::V4(_) => "0.0.0.0",
        IpAddr::V6(_) => "[::]",
    }.parse().unwrap(), 0)
}
pub fn query(q: Query, addr: IpAddr, enable_edns: bool) -> Result<Message> {
    let target = SocketAddr::new(addr, 53);
    let mut transport = try!(UdpSocket::bound(&get_bind_addr(&addr))).with_timeout(QUERY_TIMEOUT);
    match query_core(q, transport.bound(Some(&target)), enable_edns) {
        Ok(msg) => {
            if msg.is_truncated() {
                // Try TCP
                let tcp_result = TcpStream::connect_with_timeout(&target, QUERY_TIMEOUT)
                .map_err(|e| e.into())
                .and_then(|stream| stream.set_nodelay(true)
                                         .or_else(|_| Ok(()))
                                         .map(|_| stream))
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
/* FIXME: Commented out to silence warning. This may be useful again in future.
pub fn query_multiple_build_futures(q: &Query, servers: &[IpAddr]) -> Vec<Future<Result<Message>>> {
    servers.iter()
    .cloned()
    .map(move |server| {
        let qc = q.clone();
        Future::from_fn(move || query(qc, server, true))
    })
    .collect()
}
*/
pub fn query_multiple_handle_futures(futures: &mut Vec<Future<Result<Message>>>) -> Result<Message> {
    if futures.is_empty() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    loop {
        let result_index = Future::wait_any(futures);
        let result = futures.remove(result_index).consume();
        let mut should_return = futures.is_empty();
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
            Err(Error::Io(ref err)) if err.kind() == io::ErrorKind::TimedOut => {
                debug!("Timed out");
            },
            Err(ref err) => {
                debug!("Error {:?}", err);
            },
        };
        if should_return {
            return result;
        }
    }
}
/* FIXME: Commented out to silence warning. This may be useful again in future.
pub fn query_multiple(q: &Query, servers: &[IpAddr]) -> Result<Message> {
    let mut futures = query_multiple_build_futures(q, servers);
    query_multiple_handle_futures(&mut futures)
}
*/

#[cfg(test)]
mod tests {
    use trust_dns::op::*;
    use trust_dns::rr::*;

    use super::*;
    use ::mioco_config_start;

    #[test]
    fn simple_query() {
        mioco_config_start(|| {
            let mut q = Query::new();
            q.name(Name::parse("www.google.com", Some(&Name::root())).unwrap());
            let result = query(q, "8.8.8.8".parse().unwrap(), true).unwrap();
            assert!(result.get_answers().len() > 0);
        }).unwrap();
    }
}
