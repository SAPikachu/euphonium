#![feature(plugin, custom_derive)]
#![feature(downgraded_weak)]

#![cfg_attr(feature = "clippy", plugin(clippy))]
#![cfg_attr(not(feature = "clippy"), allow(unknown_lints))]
#![plugin(serde_macros)]
#![plugin(docopt_macros)]

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
extern crate serde_json;
extern crate treebitmap;
extern crate rustc_serialize;
extern crate docopt;

pub mod utils;
mod transport;
mod cache;
mod nscache;
mod query;
mod serve;
mod resolver;
pub mod config;
mod recursive;
mod forwarding;
mod control;

use std::net::{SocketAddr};

use resolver::RcResolver;
use serve::{serve_tcp, serve_udp};
use config::Config;

docopt!(Args, "
Usage: euphonium [options]
       euphonium (--help|--version)

Options:
    -c CONFIG, --config CONFIG      Specify configuration file [default: euphonium.yaml]
");
const VERSION_FULL: &'static str = concat!(
    env!("CARGO_PKG_NAME"), " ", env!("CARGO_PKG_VERSION"),
);

fn mioco_config_start_ex<F, T>(threads: usize, notify_capacity: usize, f: F) -> std::thread::Result<T>
    where F: FnOnce() -> T,
          F: Send + 'static,
          T: Send + 'static
{
    let mut config = mioco::Config::new();
    config.set_catch_panics(false);
    config.set_thread_num(threads);
    config.event_loop().notify_capacity(notify_capacity);
    mioco::Mioco::new_configured(config).start(f)
}
#[cfg(test)]
fn mioco_config_start<F, T>(f: F) -> std::thread::Result<T>
    where F: FnOnce() -> T,
          F: Send + 'static,
          T: Send + 'static
{
    let config = Config::default();
    mioco_config_start_ex(config.internal.threads, config.internal.mio_notify_capacity, f)
}
pub fn main() {
    env_logger::init().expect("What the ...?");
    let args: Args = Args::docopt().version(Some(VERSION_FULL.into())).decode()
    .unwrap_or_else(|e| e.exit());
    let config = Config::from_file(&args.flag_config)
    .unwrap_or_else(|e| {
        debug!("Error: {:?}", e);
        error!("Failed to load configuration file {}: {}", args.flag_config, e);
        std::process::exit(1);
    });

    mioco_config_start_ex(config.internal.threads, config.internal.mio_notify_capacity,
    move || {
        let ip = config.serve.ip;
        let port = config.serve.port;
        let addr = SocketAddr::new(ip, port);
        info!("Listening on {}:{}", ip, port);

        let resolver = RcResolver::new(config);
        serve_tcp(&addr, resolver.clone()).expect("Failed to initialize TCP listener");
        serve_udp(&addr, resolver).expect("Failed to initialize UDP listener");
    }).expect("Unexpected error from mioco::start");
}
