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
    pub fn resolve(&self, q: &Query) -> Result<Message> {
        query_multiple(q, &[Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(8, 8, 4, 4)]) 
    }
}
