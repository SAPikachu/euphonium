use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use mioco::tcp::TcpStream;
use mioco::udp::UdpSocket;
use rand;
use trust_dns_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};

use crate::resolver::ErrorKind as ResolverErrorKind;
use crate::transport::{DnsMsgTransport, DnsTransport};
use crate::utils::with_timeout::TcpStreamExt;
use crate::utils::{AsDisplay, Error, Future, MessageExt, Result, WithTimeout};
use crate::validator::{DummyValidator, ResponseValidator};

pub const EDNS_VER: u8 = 0;
pub const EDNS_MAX_PAYLOAD: u16 = 1200;

// Idea: Use DNSSEC to check whether a domain is poisoned by GFW

#[derive(Debug)]
pub enum ErrorKind {
    InvalidId,
    TruncatedBogus(Message),
    ValidationFailure(Message),
    UpstreamServer(Message),
}
#[derive(Eq, PartialEq, Debug, Copy, Clone)]
pub enum EdnsMode {
    Disabled,
    Enabled,
    // Required,
}

fn query_core<TTransport, TValidator>(
    q: Query,
    mut transport: TTransport,
    edns_mode: EdnsMode,
    validator: &mut TValidator,
) -> Result<Message>
where
    TTransport: DnsMsgTransport,
    TValidator: ResponseValidator,
{
    let mut msg: Message = Message::new();
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
    (transport.send_msg(&msg))?;
    let mut last_bogus_msg: Option<Message> = None;
    loop {
        let resp = (match transport.recv_msg() {
            Ok(x) => Ok(x),
            Err(e) => Err(match e {
                Error::Io(e) => match e.kind() {
                    io::ErrorKind::TimedOut if last_bogus_msg.is_some() => {
                        ErrorKind::ValidationFailure(last_bogus_msg.take().unwrap()).into()
                    }
                    io::ErrorKind::AddrNotAvailable => {
                        debug!("AddrNotAvailable -> {}", transport);
                        Error::Io(e)
                    }
                    _ => Error::Io(e),
                },
                Error::Proto(e) => {
                    warn!(
                        "[{}][{}] Failed to decode message for request {}: {:?}",
                        transport,
                        msg.id(),
                        msg.as_disp(),
                        e
                    );
                    continue;
                }
                _ => e,
            }),
        })?;
        if !resp.is_resp_for(&msg) {
            warn!(
                "[{}][{}] Invalid response for {}: {:?}",
                transport,
                msg.id(),
                msg.as_disp(),
                resp
            );
            continue;
        }
        let is_valid = match validator.is_valid(&resp) {
            Ok(x) => x,
            Err(e) => match e {
                val @ Error::Resolver(ResolverErrorKind::LostRace)
                | val @ Error::Resolver(ResolverErrorKind::AlreadyQueried) => return Err(val),
                _ => false,
            },
        };
        if !is_valid {
            if resp.truncated() {
                return Err(ErrorKind::TruncatedBogus(msg).into());
            }
            warn!(
                "[{}][{}] Rejected by validator for {}: {}",
                transport,
                msg.id(),
                msg.as_disp(),
                resp.as_disp()
            );
            last_bogus_msg = Some(resp);
            continue;
        }
        if resp.response_code() == ResponseCode::FormErr && edns_mode == EdnsMode::Enabled {
            // Maybe the server doesn't implement EDNS?
            return query_core(
                msg.queries()[0].clone(),
                transport,
                EdnsMode::Disabled,
                validator,
            );
        }
        debug!(
            "[{}] {} -> {}",
            transport,
            resp.queries()[0].as_disp(),
            resp.as_disp()
        );
        return Ok(resp);
    }
}
fn get_bind_addr(target: &SocketAddr) -> SocketAddr {
    SocketAddr::new(
        match *target {
            SocketAddr::V4(_) => "0.0.0.0",
            SocketAddr::V6(_) => "::0",
        }
        .parse()
        .unwrap(),
        0,
    )
}
pub trait IntoQueryTarget {
    fn into_target(self) -> SocketAddr;
}
impl IntoQueryTarget for SocketAddr {
    fn into_target(self) -> SocketAddr {
        self
    }
}
impl IntoQueryTarget for IpAddr {
    fn into_target(self) -> SocketAddr {
        SocketAddr::new(self, 53)
    }
}
pub fn query<T: IntoQueryTarget>(q: Query, addr: T, timeout: Duration) -> Result<Message> {
    query_with_validator(q, addr, timeout, &mut DummyValidator)
}
pub fn query_with_validator<T: ResponseValidator, TTarget: IntoQueryTarget>(
    q: Query,
    target: TTarget,
    timeout: Duration,
    validator: &mut T,
) -> Result<Message> {
    let target = target.into_target();
    let mut transport = (UdpSocket::bound(&get_bind_addr(&target)))?.with_timeout(timeout);
    macro_rules! query_tcp {
        ($q: expr) => {{
            TcpStream::connect_with_timeout(&target, timeout)
                .map_err(|e| e.into())
                .and_then(|stream| stream.set_nodelay(true).or_else(|_| Ok(())).map(|_| stream))
                .and_then(|stream| {
                    query_core(
                        $q.clone(),
                        stream.with_timeout(timeout).bound(Some(&target)),
                        EdnsMode::Enabled,
                        validator,
                    )
                })
        }};
    }
    match query_core(
        q,
        transport.bound(Some(&target)),
        EdnsMode::Enabled,
        validator,
    ) {
        Ok(msg) => {
            if msg.truncated() {
                // Try TCP
                Ok(query_tcp!(&msg.queries()[0]).unwrap_or(msg))
            } else {
                Ok(msg)
            }
        }
        Err(Error::Query(ErrorKind::TruncatedBogus(msg))) => {
            query_tcp!(&msg.queries()[0])
        }
        Err(e) => Err(e),
    }
}
pub fn query_multiple_handle_futures(
    futures: &mut Vec<Future<Result<Message>>>,
) -> Result<Message> {
    if futures.is_empty() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut last_error: Option<Error> = None;
    loop {
        let result_index = Future::wait_any(futures);
        let result = futures.remove(result_index).consume();
        let mut should_return = futures.is_empty();
        match result {
            Ok(ref msg) => {
                match msg.response_code() {
                    ResponseCode::ServFail | ResponseCode::NotImp | ResponseCode::Refused => {
                        // Fall below to wait for remaining servers, if any
                    }
                    _ => {
                        should_return = true;
                    }
                }
            }
            Err(Error::Io(ref err)) if err.kind() == io::ErrorKind::TimedOut => {
                debug!("Timed out");
            }
            Err(Error::Query(ErrorKind::ValidationFailure(ref msg))) => {
                debug!(
                    "query_multiple_handle_futures: ValidationFailure: {:?}",
                    msg
                );
            }
            Err(ref err) => {
                debug!("query_multiple_handle_futures: Error {:?}", err);
            }
        };
        if should_return {
            debug!("query_multiple_handle_futures: OK: {}", result.is_ok());
            if let Err(e) = result {
                return match e {
                    x @ Error::Resolver(ResolverErrorKind::AlreadyQueried)
                    | x @ Error::Resolver(ResolverErrorKind::LostRace) => match last_error {
                        None => Err(x),
                        Some(err) => Err(err),
                    },
                    e => Err(e),
                };
            }
            return result;
        } else {
            // Save meaningful error
            last_error = match result {
                Err(Error::Resolver(ResolverErrorKind::AlreadyQueried))
                | Err(Error::Resolver(ResolverErrorKind::LostRace)) => last_error,
                Err(e) => Some(e),
                Ok(x) => last_error.or(Some(Error::Query(ErrorKind::UpstreamServer(x)))),
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;
    use trust_dns_proto::op::*;
    use trust_dns_proto::rr::*;

    use super::*;
    use crate::mioco_config_start;

    #[test]
    fn simple_query() {
        mioco_config_start(|| {
            let mut q = Query::new();
            q.set_name(Name::parse("www.google.com", Some(&Name::root())).unwrap());
            let result =
                query::<IpAddr>(q, "8.8.8.8".parse().unwrap(), Duration::from_secs(5)).unwrap();
            assert!(result.answers().len() > 0);
        })
        .unwrap();
    }
}
