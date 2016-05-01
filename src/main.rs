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
extern crate itertools;

mod utils;
mod transport;
mod cache;
mod nscache;
mod query;
mod serve;
mod resolver;

use std::net::{SocketAddr, SocketAddrV4};
use std::sync::Arc;

use mioco::mio::Ipv4Addr;

use resolver::Resolver;
use serve::{serve_tcp, serve_udp};

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

    mioco_config_start(move || {
        let ip = Ipv4Addr::new(0, 0, 0, 0);
        let port = 5354;
        let addr = SocketAddr::V4(SocketAddrV4::new(ip, port));
        info!("Listening on {}:{}", ip, port);

        let resolver = Arc::new(Resolver::default());
        serve_tcp(&addr, resolver.clone()).expect("Failed to initialize TCP listener");
        serve_udp(&addr, resolver).expect("Failed to initialize UDP listener");
    }).expect("Unexpected error from mioco::start");
}
