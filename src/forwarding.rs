use std::sync::{Arc};
use std::net::{IpAddr};

use trust_dns::op::{Message, Query};
use itertools::Itertools;

use utils::{Result, CloneExt};
use cache::RecordSource;
use config::Config;
use resolver::RcResolver;
use query::query;

pub struct ForwardingResolver {
    server: IpAddr,
}
impl ForwardingResolver {
    pub fn create_all(config: &Config) -> Vec<Arc<Self>> {
        config.forwarders.iter()
        .map(|group| group.servers.iter().map(|server| Arc::new(ForwardingResolver {
            server: *server,
        })))
        .flatten()
        .collect_vec()
    }
    pub fn resolve(&self, q: Query, parent: RcResolver) -> Result<Message> {
        let msg = try!(query(q.clone(), self.server, *parent.config.query.timeout));
        parent.cache.update_from_message(&msg, RecordSource::Forwarder);
        Ok(msg)
    }
}
