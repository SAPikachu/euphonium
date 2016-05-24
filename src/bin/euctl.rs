#![feature(plugin)]

#![cfg_attr(feature = "clippy", plugin(clippy))]
#![cfg_attr(not(feature = "clippy"), allow(unknown_lints))]
#![plugin(docopt_macros)]

extern crate serde_json;
extern crate docopt;
extern crate rustc_serialize;
extern crate env_logger;
extern crate eulib;
extern crate mioco;

use std::io::Write;

use mioco::unix::UnixSocket;

use eulib::utils::{JsonRpcRequest, JsonRpcResponse};
use eulib::config::Config;

docopt!(Args, "
Usage: euctl [-s SOCK] <command>
       euctl (--help|--version)

Options:
    -s SOCK, --sock SOCK      Specify where the control socket is located at. If not specified, default location will be used.
");
const VERSION_FULL: &'static str = concat!(
    "euctl ", env!("CARGO_PKG_VERSION"),
);

fn main() {
    env_logger::init().expect("What the ...?");
    let args: Args = Args::docopt().version(Some(VERSION_FULL.into())).decode()
    .unwrap_or_else(|e| e.exit());
    let mut sock_path = args.flag_sock.clone();
    if sock_path.is_empty() {
        sock_path.push_str(&Config::default().control.sock_path);
    }
    let req = JsonRpcRequest::new(args.arg_command);
    mioco::start(move || {
        let stream = UnixSocket::stream().unwrap();
        let (mut socket, _) = stream.connect(&sock_path).unwrap();
        serde_json::to_writer(&mut socket, &req).unwrap();
        socket.write_all(b"\n").unwrap();
        socket.flush().unwrap();
        let resp: JsonRpcResponse = serde_json::from_reader(&mut socket).unwrap();
        if let Some(msg) = resp.result {
            println!("Success: {}", msg);
            std::process::exit(0);
        } else {
            println!("Error: {}", resp.error.unwrap());
            std::process::exit(1);
        }
    }).unwrap();
}
