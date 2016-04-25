use std::sync::Arc;

use mioco::mio::Ipv4Addr;
use trust_dns::op::{Message, ResponseCode, Edns, OpCode, Query};
use trust_dns::rr::DNSClass;

use utils::{Result, Error, CloneExt, MessageExt};
use query::{query_multiple};
use cache::Cache;

// Idea: Use DNSSEC to check whether a domain is poisoned by GFW

#[derive(Default)]
pub struct Resolver {
    cache: Cache,
}
pub type RcResolver = Arc<Resolver>;
impl Resolver {
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
        let resp = try!(query_multiple(&msg.get_queries()[0], &[Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(8, 8, 4, 4)]));
        entry.lock().unwrap().update(&resp);
        msg.copy_resp_from(&resp);
        Ok(())
    }
}
