use std::sync::{Arc, Weak};
use std::default::Default;
use std::net::{IpAddr};

use mioco;
use trust_dns::op::{Message, ResponseCode, Query};
use trust_dns::rr::{Name};

use utils::{Result, MessageExt, AsDisplay};
use cache::Cache;
use nscache::NsCache;
use config::Config;
use resolver::RcResolver;

pub struct ForwardingResolver {
    server: IpAddr,
    parent: RcResolver,
}
impl ForwardingResolver {
    fn resolve(&self, q: &Query) -> Result<Message> {
        unimplemented!();
    }
}
