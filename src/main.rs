#![feature(plugin, custom_derive)]
#![plugin(clippy)]
#![plugin(serde_macros)]
#![plugin(docopt_macros)]

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
extern crate treebitmap;
extern crate rustc_serialize;
extern crate docopt;

mod utils;
mod transport;
mod cache;
mod nscache;
mod query;
mod serve;
mod resolver;
mod config;
mod recursive;
mod forwarding;

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
    let args: Args = Args::docopt().decode().unwrap_or_else(|e| e.exit());
    let config = Config::from_file(&args.flag_config)
    .unwrap_or_else(|e| {
        debug!("Error: {:?}", e);
        error!("Failed to load configuration file {}: {}", args.flag_config, e);
        std::process::exit(1);
    });

    mioco_config_start(move || {
        let ip = config.serve.ip;
        let port = config.serve.port;
        let addr = SocketAddr::new(ip, port);
        info!("Listening on {}:{}", ip, port);

        let resolver = RcResolver::new(config);
        serve_tcp(&addr, resolver.clone()).expect("Failed to initialize TCP listener");
        serve_udp(&addr, resolver).expect("Failed to initialize UDP listener");
    }).expect("Unexpected error from mioco::start");
}
