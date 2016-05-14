#![feature(plugin, custom_derive)]
#![plugin(clippy)]
#![plugin(serde_macros)]

#![feature(downgraded_weak)]

#![recursion_limit="128"]

extern crate env_logger;
extern crate mio;
#[macro_use] extern crate mioco;
extern crate trust_dns;
extern crate rand;
#[macro_use] extern crate quick_error;
#[macro_use] extern crate log;
extern crate byteorder;
extern crate itertools;
#[macro_use] extern crate custom_derive;
#[macro_use] extern crate newtype_derive;
extern crate serde;
extern crate serde_yaml;

mod utils;
mod transport;
mod cache;
mod nscache;
mod query;
mod serve;
mod resolver;
mod config;

use std::net::{SocketAddr};

use resolver::RcResolver;
use serve::{serve_tcp, serve_udp};
use config::Config;

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
        let config = Config::default();
        let ip = config.serve.ip;
        let port = config.serve.port;
        let addr = SocketAddr::new(ip, port);
        info!("Listening on {}:{}", ip, port);

        let resolver = RcResolver::new(config);
        serve_tcp(&addr, resolver.clone()).expect("Failed to initialize TCP listener");
        serve_udp(&addr, resolver).expect("Failed to initialize UDP listener");
    }).expect("Unexpected error from mioco::start");
}
