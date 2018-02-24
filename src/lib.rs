#![allow(unknown_lints)]

#![recursion_limit="128"]

extern crate env_logger;
extern crate mio;
#[macro_use] extern crate mioco;
extern crate trust_dns;
extern crate trust_dns_proto;
extern crate rand;
#[macro_use] extern crate quick_error;
#[macro_use] extern crate log;
extern crate byteorder;
extern crate itertools;
#[macro_use] extern crate macro_attr;
#[macro_use] extern crate newtype_derive;
extern crate serde;
#[macro_use] extern crate serde_derive;
extern crate serde_yaml;
extern crate serde_json;
extern crate treebitmap;
extern crate docopt;
extern crate parking_lot;
extern crate chrono;
extern crate time;
extern crate yaml_rust;
#[macro_use] extern crate lazy_static;
extern crate data_encoding;
extern crate nix;
extern crate privdrop;
extern crate linked_hash_map;
extern crate pnet_datalink;

#[cfg(test)]
extern crate rustc_serialize;
#[cfg(test)]
extern crate timebomb;

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
mod validator;

use std::net::{SocketAddr};

use docopt::Docopt;

use resolver::RcResolver;
use serve::{serve_tcp, serve_udp};
use config::Config;

const USAGE: &'static str = "
Usage: euphonium [options]
       euphonium (--help|--version)

Options:
    -c CONFIG, --config CONFIG      Specify configuration file [default: euphonium.yaml]
    -t, --test                      Test configuration and then exit immediately
";
#[derive(Debug, Deserialize)]
struct Args {
    flag_config: String,
    flag_test: bool,
}
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
    timebomb::timeout_ms(|| {
        let config = Config::default();
        mioco_config_start_ex(
            config.internal.threads,
            config.internal.mio_notify_capacity,
            f,
        )
    }, 30000)
}
pub fn main() {
    env_logger::init();
    let args: Args = Docopt::new(USAGE).unwrap()
    .version(Some(VERSION_FULL.into()))
    .deserialize()
    .unwrap_or_else(|e| e.exit());
    let config = Config::from_file(&args.flag_config)
    .unwrap_or_else(|e| {
        debug!("Error: {:?}", e);
        error!("Failed to load configuration file {}: {}", args.flag_config, e);
        std::process::exit(1);
    });
    if args.flag_test {
        return;
    }
    let pd = {
        let mut pd = privdrop::PrivDrop::default();
        if let Some(user) = config.serve.setuid.as_ref() {
            pd = pd.user(user);
            if let Some(group) = config.serve.setgid.as_ref() {
                pd = pd.group(group);
            }
            Some(pd)
        } else if config.serve.setgid.is_some() {
            error!("Config: Can't set serve.setgid when serve.setuid is empty");
            std::process::exit(1);
        } else {
            None
        }
    };
    if args.flag_test {
        return;
    }
    mioco_config_start_ex(config.internal.threads, config.internal.mio_notify_capacity,
    move || {
        let ip = config.serve.ip;
        let port = config.serve.port;
        let addr = SocketAddr::new(ip, port);
        info!("Listening on {}:{}", ip, port);

        let resolver = RcResolver::new(config);
        serve_tcp(&addr, resolver.clone()).expect("Failed to initialize TCP listener");
        serve_udp(&addr, resolver).expect("Failed to initialize UDP listener");
        if nix::unistd::geteuid() == 0 {
            if let Some(pdobj) = pd {
                pdobj.apply().expect("Failed to drop privileges");
            } else {
                warn!("Running under root")
            }
        }
    }).expect("Unexpected error from mioco::start");
}
