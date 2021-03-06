extern crate serde;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;
extern crate docopt;
extern crate env_logger;
extern crate eulib;
extern crate mioco;

use std::io::Write;

use docopt::Docopt;
use mioco::unix::UnixSocket;

use eulib::config::Config;
use eulib::utils::{JsonRpcRequest, JsonRpcResponse};

const USAGE: &'static str = "
Usage: euctl [-s SOCK] <command> [<params>...]
       euctl (--help|--version)

Options:
    -s SOCK, --sock SOCK      Specify where the control socket is located at. If not specified, default location will be used.
";
#[derive(Debug, Deserialize)]
struct Args {
    flag_sock: String,
    arg_command: String,
    arg_params: Vec<String>,
}
const VERSION_FULL: &'static str = concat!("euctl ", env!("CARGO_PKG_VERSION"),);

fn main() {
    env_logger::init();
    let args: Args = Docopt::new(USAGE)
        .unwrap()
        .version(Some(VERSION_FULL.into()))
        .deserialize()
        .unwrap_or_else(|e| e.exit());
    let mut sock_path = args.flag_sock.clone();
    if sock_path.is_empty() {
        sock_path.push_str(&Config::default().control.sock_path);
    }
    let req = JsonRpcRequest::new(args.arg_command, args.arg_params);
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
    })
    .unwrap();
}
