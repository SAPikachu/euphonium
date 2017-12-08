use std::net::{SocketAddr, IpAddr};
use std::io;
use std::time::Duration;

use rand;
use mioco::udp::UdpSocket;
use mioco::tcp::{TcpStream};
use trust_dns::op::{Message, MessageType, ResponseCode, Query, OpCode, Edns};

use utils::{Result, Error, MessageExt, WithTimeout, Future, AsDisplay};
use utils::with_timeout::TcpStreamExt;
use transport::{DnsTransport, DnsMsgTransport};
use validator::{ResponseValidator, DummyValidator};
use resolver::ErrorKind as ResolverErrorKind;

pub const EDNS_VER: u8 = 0;
pub const EDNS_MAX_PAYLOAD: u16 = 1200;

// Idea: Use DNSSEC to check whether a domain is poisoned by GFW

#[derive(Debug)]
pub enum ErrorKind {
    InvalidId,
    TruncatedBogus(Message),
    ValidationFailure(Message),
}
#[derive(Eq, PartialEq, Debug, Copy, Clone)]
pub enum EdnsMode {
    Disabled,
    Enabled,
    // Required,
}

fn query_core<TTransport, TValidator>(q: Query, mut transport: TTransport, edns_mode: EdnsMode, validator: &mut TValidator) -> Result<Message> where TTransport: DnsMsgTransport, TValidator: ResponseValidator {
    let mut msg : Message = Message::new();
    msg.set_message_type(MessageType::Query);
    msg.set_id(rand::random());
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);
    if edns_mode != EdnsMode::Disabled {
        let mut edns = Edns::new();
        edns.set_version(EDNS_VER);
        edns.set_max_payload(EDNS_MAX_PAYLOAD);
        validator.prepare_msg(&mut msg, &mut edns);
        msg.set_edns(edns);
    }
    msg.add_query(q);
    debug!("[{}] {}", transport, msg.as_disp());
    try!(transport.send_msg(&msg));
    let mut last_bogus_msg: Option<Message> = None;
    loop {
        let resp = try!(match transport.recv_msg() {
            Ok(x) => Ok(x),
            Err(e) => Err(match e {
                Error::Io(e) => {
                    match e.kind() {
                        io::ErrorKind::TimedOut if last_bogus_msg.is_some() => {
                            ErrorKind::ValidationFailure(
                                last_bogus_msg.take().unwrap()
                            ).into()
                        },
                        _ => Error::Io(e),
                    }
                },
                Error::Decode(e) => {
                    warn!("Failed to decode message: {:?}", e);
                    continue
                },
                _ => e,
            }),
        });
        if ! resp.is_resp_for(&msg) {
            warn!("[{}][{}] Invalid response for {}: {:?}",
                  transport, msg.id(), msg.as_disp(), resp);
            continue;
        }
        let is_valid = match validator.is_valid(&resp) {
            Ok(x) => x,
            Err(e) => {
                match e {
                    val @ Error::Resolver(ResolverErrorKind::LostRace) |
                    val @ Error::Resolver(ResolverErrorKind::AlreadyQueried) => {
                        return Err(val)
                    },
                    _ => false,
                }
            },
        };
        if !is_valid {
            if resp.truncated() {
                return Err(ErrorKind::TruncatedBogus(msg).into());
            }
            warn!("[{}][{}] Rejected by validator for {}: {}",
                  transport, msg.id(), msg.as_disp(), resp.as_disp());
            last_bogus_msg = Some(resp);
            continue;
        }
        if resp.response_code() == ResponseCode::FormErr &&
            edns_mode == EdnsMode::Enabled
        {
            // Maybe the server doesn't implement EDNS?
            return query_core(
                msg.queries()[0].clone(), transport, EdnsMode::Disabled, validator,
            );
        }
        debug!("[{}] {} -> {}", transport, resp.queries()[0].as_disp(), resp.as_disp());
        return Ok(resp);
    }
}
fn get_bind_addr(target: &IpAddr) -> SocketAddr {
    SocketAddr::new(match *target {
        IpAddr::V4(_) => "0.0.0.0",
        IpAddr::V6(_) => "::0",
    }.parse().unwrap(), 0)
}
pub fn query(q: Query, addr: IpAddr, timeout: Duration) -> Result<Message> {
    query_with_validator(q, addr, timeout, &mut DummyValidator)
}
pub fn query_with_validator<T: ResponseValidator>(q: Query, addr: IpAddr, timeout: Duration, validator: &mut T) -> Result<Message> {
    let target = SocketAddr::new(addr, 53);
    let mut transport = try!(UdpSocket::bound(&get_bind_addr(&addr))).with_timeout(timeout);
    macro_rules! query_tcp {
        ($q: expr) => {{
            TcpStream::connect_with_timeout(&target, timeout)
            .map_err(|e| e.into())
            .and_then(|stream| stream.set_nodelay(true)
                                     .or_else(|_| Ok(()))
                                     .map(|_| stream))
            .and_then(|stream| query_core(
                $q.clone(),
                stream.with_timeout(timeout).bound(Some(&target)),
                EdnsMode::Enabled,
                validator,
            ))
        }}
    };
    match query_core(q, transport.bound(Some(&target)), EdnsMode::Enabled, validator) {
        Ok(msg) => {
            if msg.truncated() {
                // Try TCP
                Ok(query_tcp!(&msg.queries()[0]).unwrap_or(msg))
            } else {
                Ok(msg)
            }
        },
        Err(Error::Query(ErrorKind::TruncatedBogus(msg))) => {
            query_tcp!(&msg.queries()[0])
        },
        Err(e) => Err(e),
    }
}
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
                match msg.response_code() {
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
            Err(Error::Query(ErrorKind::ValidationFailure(ref msg))) => {
                trace!("ValidationFailure: {:?}", msg);
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

#[cfg(test)]
mod tests {
    use std::time::Duration;
    use trust_dns::op::*;
    use trust_dns::rr::*;

    use super::*;
    use ::mioco_config_start;

    #[test]
    fn simple_query() {
        mioco_config_start(|| {
            let mut q = Query::new();
            q.set_name(Name::parse("www.google.com", Some(&Name::root())).unwrap());
            let result = query(q, "8.8.8.8".parse().unwrap(), Duration::from_secs(5)).unwrap();
            assert!(result.answers().len() > 0);
        }).unwrap();
    }
}
