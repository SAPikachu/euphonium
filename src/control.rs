use std;
use std::io::{Result, BufReader, BufRead, Write};
use std::os::unix::fs::PermissionsExt;
use std::fs::{metadata, set_permissions, remove_file};
use std::sync::mpsc::TryRecvError;
use std::fmt::{Debug, Display};

use mioco;
use mioco::sync::mpsc::{channel, Sender, Receiver};
use mioco::unix::UnixListener;
use serde_json;

use resolver::{RcResolver};
use utils::{WithTimeout, JsonRpcRequest};

pub trait FormattableError: std::error::Error + Display + Debug {}
impl<T> FormattableError for T where T: std::error::Error + Display + Debug {}
quick_error! {
    #[derive(Debug)]
    pub enum Error {
        UnknownCommand {
            description("Unknown command")
        }
        Wrapped(inner: Box<FormattableError>) {
            description(inner.description())
            from()
            display("{}", inner)
        }
        Custom(msg: String) {
            description("Custom error")
            display("{}", msg)
        }
    }
}
pub type ControlResult = std::result::Result<String, Error>;
pub struct ControlServer {
    #[allow(dead_code)]
    live_keeper: Sender<()>,
    notifier: Option<Receiver<()>>,
}
impl Default for ControlServer {
    fn default() -> Self {
        Self::new()
    }
}
impl ControlServer {
    pub fn new() -> Self {
        let (send, recv) = channel::<()>();
        ControlServer {
            live_keeper: send,
            notifier: Some(recv),
        }
    }
    pub fn run(&mut self, resolver: &RcResolver) -> Result<()> {
        let notifier = self.notifier.take().expect("run() can only be called once");
        ControlServer::serve(resolver, notifier)
    }
    fn serve(resolver: &RcResolver, live_notifier: Receiver<()>) -> Result<()> {
        let sock_path = &resolver.config.control.sock_path;
        // Clean up old socket
        remove_file(sock_path).is_ok();
        let listener = try!(UnixListener::bind(sock_path));
        let mut perm = try!(metadata(sock_path)).permissions();
        perm.set_mode(**resolver.config.control.sock_permission);
        try!(set_permissions(sock_path, perm));
        let weak = resolver.to_weak();
        mioco::spawn(move || {
            loop {
                debug!("Selecting");
                select!(
                    r:listener => {
                        /* Fall below */
                    },
                    r:live_notifier => {
                        match live_notifier.try_recv() {
                            Ok(_) => panic!("Nothing should be sent over this channel"),
                            Err(TryRecvError::Disconnected) => {
                                debug!("Resolver is dropped, closing control channel");
                                return;
                            },
                            Err(TryRecvError::Empty) => { /* Spurious wakeup */ },
                        };
                    },
                );
                let resolver = match weak.upgrade() {
                    Some(x) => x,
                    None => {
                        debug!("Resolver is dropped, closing control channel");
                        return;
                    },
                };
                let result = listener.try_accept()
                .expect("Unable to accept from control socket");
                let sock = match result {
                    Some(sock) => sock,
                    None => continue,
                };
                let sock = sock.with_resetting_timeout(5000);
                let mut reader = BufReader::new(sock);
                let mut buf = String::new();
                if let Err(e) = reader.read_line(&mut buf) {
                    warn!("Failed to read from control socket: {:?}", e);
                    continue;
                }
                let req: JsonRpcRequest = match serde_json::from_str(&buf) {
                    Ok(x) => x,
                    Err(e) => {
                        warn!(
                            "Control socket received an invalid request: {}, {:?}",
                            buf, e,
                        );
                        continue
                    },
                };
                info!("Command: {}", req.method);
                let resp = match resolver.handle_control_command(
                    &req.method, &req.params,
                ) {
                    Ok(x) => req.result(x),
                    Err(e) => req.error(e.to_string()),
                };
                let mut resp_str = serde_json::to_string(&resp).unwrap();
                resp_str.push_str("\n");
                let mut sock = reader.into_inner();
                if let Err(e) = sock.write_all(resp_str.as_bytes()) {
                    warn!("Failed to write to control socket: {:?}", e);
                }
            }
        });
        Ok(())
    }
}
