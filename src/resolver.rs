use std::sync::Arc;
use std::net::IpAddr;
use std::io::ErrorKind;

use mioco::mio::Ipv4Addr;
use trust_dns::op::{Message, ResponseCode, Edns, OpCode, Query};
use trust_dns::rr::{DNSClass, Name};

use utils::{Result, Error, CloneExt, MessageExt};
use query::{query_multiple};
use cache::Cache;
use nscache::NsCache;

// Idea: Use DNSSEC to check whether a domain is poisoned by GFW

#[derive(Default)]
pub struct Resolver {
    cache: Cache,
    nscache: NsCache,
}
pub type RcResolver = Arc<Resolver>;
impl Resolver {
    fn resolve_recursive(&self, q: &Query) -> Result<Message> {
        unimplemented!();
        loop {
            let ns = self.nscache.lookup_recursive(&q.get_name());
            assert!(ns.len() > 0);
            // TODO: We need to make it smarter
            let result = try!(query_multiple(q, &ns));
            if result.get_response_code() != ResponseCode::NoError {
                return Ok(result);
            }
            if !result.get_answers().is_empty() {
                // TODO: Anything else to do?
                return Ok(result);
            }
            if result.get_name_servers().is_empty() {
                warn!("Nameserver returned NOERROR and empty answer");
                return Err(ErrorKind::InvalidData.into());
            }
        }
    }
    pub fn resolve(&self, msg: &mut Message) -> Result<()> {
        debug_assert!(msg.get_queries().len() == 1);
        debug_assert!(msg.get_answers().is_empty());
        debug_assert!(msg.get_name_servers().is_empty());
        let entry = self.cache.lookup(msg.get_queries()[0].get_name());
        match entry.lock().unwrap().lookup(&msg.get_queries()[0].get_query_type()) {
            None => {},
            Some(cached) => {
                msg.copy_resp_from(cached);
                return Ok(());
            },
        };
        let resp = try!(query_multiple(&msg.get_queries()[0], &[IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4))]));
        entry.lock().unwrap().update(&resp);
        msg.copy_resp_from(&resp);
        Ok(())
    }
}
