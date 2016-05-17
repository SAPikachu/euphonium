use std::sync::{Arc};
use std::net::{IpAddr};

use trust_dns::op::{Message, Query};
use trust_dns::rr::RData;
use itertools::Itertools;

use utils::{Result, CloneExt};
use cache::RecordSource;
use config::Config;
use resolver::{RcResolver, ErrorKind};
use query::query;
use utils::IpSet;

pub struct ForwardingResolver {
    server: IpAddr,
    accepted_ips: Option<Arc<IpSet>>,
}
impl ForwardingResolver {
    pub fn create_all(config: &Config) -> Vec<Arc<Self>> {
        config.forwarders.iter()
        .map(|group| group.servers.iter().map(|server| Arc::new(ForwardingResolver {
            server: *server,
            accepted_ips: group.accepted_ip_list.as_ref().map(|x| (**x).clone()),
        })).collect_vec())
        .flatten()
        .collect_vec()
    }
    pub fn resolve(&self, q: Query, parent: RcResolver) -> Result<Message> {
        let msg = try!(query(q.clone(), self.server, *parent.config.query.timeout));
        if let Some(ref ipset) = self.accepted_ips {
            if msg.get_answers().iter().any(|x| if let RData::A {address} = *x.get_rdata() {
                !ipset.test(IpAddr::V4(address))
            } else { false }) {
                // Not in accepted IP list
                return Err(ErrorKind::RejectedIp.into());
            }
        }
        parent.cache.update_from_message(&msg, RecordSource::Forwarder);
        Ok(msg)
    }
}
