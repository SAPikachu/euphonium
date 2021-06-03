use std::fmt;
use std::fmt::Display;
use std::io;
use std::io::{Read, Write};

use std::net::SocketAddr;

use mioco::tcp::TcpStream;
use mioco::udp::UdpSocket;
use trust_dns_proto::op::Message;
use trust_dns_proto::serialize::binary::{BinDecodable, BinEncodable};

use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};

use crate::utils::with_timeout::WithTimeoutState;
use crate::utils::Result;

pub trait DnsTransport {
    /// Receives a DNS message via transport. If `addr` is specified and this is an UDP transport,
    /// only messages from the specified address will be accepted, everything else will be
    /// discarded.
    fn recv_msg_bytes(
        &mut self,
        addr: Option<&SocketAddr>,
    ) -> io::Result<(Vec<u8>, Option<SocketAddr>)>;
    /// Sends a DNS message via this transport. `addr` is required for UDP transport, and ignored
    /// for TCP transport.
    fn send_msg_bytes(&mut self, buf: &[u8], addr: Option<&SocketAddr>) -> io::Result<()>;
    fn transport_name() -> &'static str;
    fn should_truncate() -> bool {
        true
    }
    fn recv_msg(&mut self, addr: Option<&SocketAddr>) -> Result<(Message, Option<SocketAddr>)> {
        let (bytes, addr) = (self.recv_msg_bytes(addr))?;
        let msg = (Message::from_bytes(&bytes))?;
        Ok((msg, addr))
    }
    fn send_msg(&mut self, msg: &Message, addr: Option<&SocketAddr>) -> Result<()> {
        let bytes = (msg.to_bytes())?;
        self.send_msg_bytes(&bytes, addr).map_err(|e| e.into())
    }
    fn bound<'a>(&'a mut self, addr: Option<&'a SocketAddr>) -> BoundDnsTransport<'a, Self> {
        BoundDnsTransport {
            transport: self,
            addr: addr,
        }
    }
}
pub struct BoundDnsTransport<'a, T: ?Sized>
where
    T: DnsTransport + 'a,
{
    transport: &'a mut T,
    addr: Option<&'a SocketAddr>,
}
pub trait DnsMsgTransport: Display {
    fn recv_msg(&mut self) -> Result<Message>;
    fn send_msg(&mut self, msg: &Message) -> Result<()>;
}
impl<'a, T> DnsMsgTransport for BoundDnsTransport<'a, T>
where
    T: DnsTransport + 'a,
{
    fn recv_msg(&mut self) -> Result<Message> {
        let (msg, addr) = (self.transport.recv_msg(self.addr))?;
        debug_assert!(
            addr.as_ref() == self.addr || self.addr.is_none() || addr.is_none(),
            "recv_msg address mismatch: {}, expected: {:?}, got: {:?}",
            self,
            self.addr,
            addr,
        );
        Ok(msg)
    }
    fn send_msg(&mut self, msg: &Message) -> Result<()> {
        self.transport.send_msg(msg, self.addr)
    }
}
impl<'a, T> fmt::Display for BoundDnsTransport<'a, T>
where
    T: DnsTransport + 'a,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}({})",
            T::transport_name(),
            match self.addr {
                None => "any".into(),
                Some(x) => format!("{}", *x),
            }
        )
    }
}
macro_rules! impl_tcp_transport {
    () => {
        fn recv_msg_bytes(
            &mut self,
            _: Option<&SocketAddr>,
        ) -> io::Result<(Vec<u8>, Option<SocketAddr>)> {
            let len = (self.read_u16::<NetworkEndian>())? as usize;
            let mut buf = vec![0u8; len];
            (self.read_exact(&mut buf))?;
            Ok((buf, None))
        }
        fn send_msg_bytes(&mut self, buf: &[u8], _: Option<&SocketAddr>) -> io::Result<()> {
            if buf.len() > 65535 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Message is too big",
                ));
            }
            (self.write_u16::<NetworkEndian>(buf.len() as u16))?;
            self.write_all(buf)
        }
        fn transport_name() -> &'static str {
            "tcp"
        }
        fn should_truncate() -> bool {
            false
        }
    };
}
impl DnsTransport for TcpStream {
    impl_tcp_transport!();
}
impl DnsTransport for WithTimeoutState<TcpStream> {
    impl_tcp_transport!();
}

macro_rules! impl_udp_transport {
    () => {
        fn recv_msg_bytes(
            &mut self,
            expected_addr: Option<&SocketAddr>,
        ) -> io::Result<(Vec<u8>, Option<SocketAddr>)> {
            let mut buf = vec![0u8; 4096];
            loop {
                let (len, addr) = (self.recv(buf.as_mut_slice()))?;
                match expected_addr {
                    None => {}
                    Some(ref x) => {
                        if addr != **x {
                            debug!("Received packet from unexpected endpoint: {}", addr);
                            continue;
                        }
                    }
                };
                buf.truncate(len);
                return Ok((buf, Some(addr)));
            }
        }
        fn send_msg_bytes(&mut self, buf: &[u8], addr: Option<&SocketAddr>) -> io::Result<()> {
            assert!(addr.is_some());
            match self.send(buf, addr.unwrap()) {
                Ok(len) => {
                    assert_eq!(len, buf.len());
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }
        fn transport_name() -> &'static str {
            "udp"
        }
    };
}
impl DnsTransport for UdpSocket {
    impl_udp_transport!();
}
impl DnsTransport for WithTimeoutState<UdpSocket> {
    impl_udp_transport!();
}
