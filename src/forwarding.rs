use std::sync::{Arc};
use std::net::{IpAddr};

use trust_dns::op::{Message, Query};
use trust_dns::rr::RData;
use itertools::Itertools;

use utils::{Result};
use cache::RecordSource;
use config::Config;
use resolver::{RcResolver, ErrorKind};
use query::query;
use utils::{IpSet, MessageExt};

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
        if !msg.answers().iter().any(|x| x.rr_type() == q.query_type()) {
            // Invalid response
            return Err(ErrorKind::RejectedIp.into());
        }
        if let Some(ref ipset) = self.accepted_ips {
            // FIXME: Do we need IPv6 here?
            if msg.answers().iter().any(|x| if let RData::A(address) = *x.rdata()
                { !ipset.test(IpAddr::V4(address)) } else { false })
            {
                // Not in accepted IP list
                return Err(ErrorKind::RejectedIp.into());
            }
        }
        // Treat all messages from forwarder as non-authenticated
        let msg = msg.strip_dnssec_records();
        parent.cache.update_from_message(&msg, RecordSource::Forwarder);
        // Set TTL to 1 second so that clients can come back and fetch better result
        let mut ret = Message::new();
        ret.copy_resp_with(&msg, |rec| {
            let mut new_rec = rec.clone();
            new_rec.set_ttl(1);
            new_rec
        });
        Ok(ret)
    }
}
