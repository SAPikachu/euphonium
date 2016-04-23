#![allow(unused_imports)]

use std::net::{SocketAddr, SocketAddrV4, IpAddr};
use std::cmp::max;

use mioco;
use mioco::JoinHandle;
use mioco::udp::UdpSocket;
use mioco::tcp::{TcpListener, TcpStream};
use mioco::mio::Ipv4Addr;
use mioco::sync::mpsc::{channel};
use trust_dns::op::{Message, MessageType, ResponseCode, Query, OpCode, Edns};

use utils::{Result, Error, CloneExt, MessageExt, WithTimeout, Future};
use utils::with_timeout::TcpStreamExt;
use transport::{DnsTransport, BoundDnsTransport};

#[test]
fn connect_with_timeout_success() {
    super::mioco_config_start(|| {
        let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53);
        TcpStream::connect_with_timeout(&target, 5000).unwrap();
    }).unwrap();
}
#[test]
#[should_panic(expected = "refused")]
fn connect_with_timeout_refused() {
    super::mioco_config_start(|| {
        let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 65534);
        TcpStream::connect_with_timeout(&target, 5000).unwrap();
    }).unwrap();
}
#[test]
#[should_panic(expected = "TimedOut")]
fn connect_with_timeout_timeout() {
    super::mioco_config_start(|| {
        let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(202, 96, 128, 68)), 65534);
        TcpStream::connect_with_timeout(&target, 10).unwrap();
    }).unwrap();
}
