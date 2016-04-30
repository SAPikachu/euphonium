use std::sync::Arc;
use std::net::IpAddr;
use std::collections::{HashMap, HashSet};
use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::default::Default;
use std::str::FromStr;

use mioco::mio::Ipv4Addr;
use mioco::sync::Mutex;
use trust_dns::op::{Message, ResponseCode, Edns, OpCode, Query};
use trust_dns::rr::{DNSClass, Name, RecordType, RData};
use itertools::Itertools;

use utils::{Result, Error as TopError, CloneExt, MessageExt, Future};
use query::{query_multiple, query_multiple_handle_futures, query as query_one};
use cache::Cache;
use nscache::RcNsCache;

// Idea: Use DNSSEC to check whether a domain is poisoned by GFW

#[derive(Debug, Clone)]
pub enum ErrorKind {
    NoNameserver,
    EmptyAnswer,
    InsaneNsReferral,
}

pub struct Resolver {
    cache: Cache,
    ns_cache: RcNsCache,
}
pub type RcResolver = Arc<Resolver>;

struct RecursiveResolverState {
    queried_ips: Mutex<HashSet<IpAddr>>,
    query: Query,
    ns_cache: RcNsCache,
}
impl RecursiveResolverState {
    fn new(q: &Query, ns_cache: RcNsCache) -> Self {
        RecursiveResolverState {
            queried_ips: Mutex::new(Default::default()),
            query: q.clone(),
            ns_cache: ns_cache,
        }
    }
}
#[derive(Clone)]
struct RecursiveResolver {
    state: Arc<RecursiveResolverState>,
}
impl RecursiveResolver {
    fn query(&self) -> Result<Message> {
        let ns = self.state.ns_cache.lookup_recursive(&self.state.query.get_name());
        self.query_ns_multiple(&ns)
    }
    fn query_ns_multiple(&self, ns: &[IpAddr]) -> Result<Message> {
        let mut futures: Vec<_> = ns.iter().filter_map(|x| self.query_ns_future(x)).collect();
        if futures.is_empty() {
            return Err(ErrorKind::NoNameserver.into());
        }
        query_multiple_handle_futures(&mut futures)
    }
    fn query_ns_future(&self, ns: &IpAddr) -> Option<Future<Result<Message>>> {
        {
            let mut guard = self.state.queried_ips.lock().unwrap();
            if guard.contains(ns) {
                return None;
            }
            if guard.len() > 256 {
                debug_assert!(false);
                warn!("Already queried too many servers for {:?}, bug or attack?", self.state.query);
                return None;
            }
            guard.insert(*ns);
        }
        let inst = self.clone();
        let ns_clone = *ns;
        Some(Future::from_fn(move || inst.query_ns(ns_clone)))
    }
    fn query_ns(self, ns: IpAddr) -> Result<Message> {
        let result = try!(query_one(self.state.query.clone(), ns, true));
        if result.get_response_code() != ResponseCode::NoError {
            return Ok(result);
        }
        if !result.get_answers().is_empty() {
            // TODO: Handle CNAME-only response
            // TODO: Update main cache if this response is more preferable
            // TODO: Anything else to do?
            return Ok(result);
        }
        self.handle_ns_referral(&result)
    }
    fn handle_ns_referral(&self, msg: &Message) -> Result<Message> {
        let mut ns_domains : HashMap<_, _> = msg.get_name_servers().iter()
        .filter_map(|x| match *x.get_rdata() {
            RData::NS {ref nsdname} => Some((nsdname.clone(), x.get_name().clone())),
            _ => None,
        })
        .collect();
        if ns_domains.is_empty() {
            warn!("Nameserver returned NOERROR and empty answer");
            return Err(ErrorKind::EmptyAnswer.into());
        }
        if ns_domains.values().dedup().count() > 1 {
            // FIXME: Is this legal?
            debug_assert!(false);
            warn!("Nameserver returned NS records for multiple zones");
            return Err(ErrorKind::InsaneNsReferral.into());
        }
        let referred_zone = ns_domains.values().next().unwrap().clone();
        if !referred_zone.zone_of(msg.get_queries()[0].get_name()) {
            warn!("Nameserver returned NS records for incorrect zone");
            return Err(ErrorKind::InsaneNsReferral.into());
        }
        debug!("NS referral: {}", referred_zone);

        // Get IPs of all NSes.
        let ns_items: Vec<_> = msg.get_additional().iter()
        .filter(|x| ns_domains.contains_key(x.get_name()))
        .filter_map(|x| match *x.get_rdata() {
            RData::A {ref address} => Some((IpAddr::V4(*address), x.get_name().clone())),
            RData::AAAA {ref address} => Some((IpAddr::V6(*address), x.get_name().clone())),
            _ => None,
        })
        .collect();
        {
            let mut guard = self.state.ns_cache.lock().unwrap();
            let entry = guard.lookup_or_insert(&referred_zone);
            for &(ref ip, ref name) in &ns_items {
                ns_domains.remove(name);
                entry.add_ns(*ip, name.clone());
            }
        }
        for name in ns_domains.keys() {
            // TODO: Resolve these NSes manually
            warn!("No glue record for {}", name);
        }
        self.query_ns_multiple(&ns_items.iter().map(|x| x.0).collect::<Vec<_>>())
    }
    fn resolve(q: &Query, ns_cache: RcNsCache) -> Result<Message> {
        let resolver = RecursiveResolver {
            state: Arc::new(RecursiveResolverState::new(q, ns_cache)),
        };
        resolver.query()
    }
}
impl Resolver {
    fn init_root_servers(&self) {
        let mut guard = self.ns_cache.lock().unwrap();
        let mut entry = guard.lookup_or_insert(&Name::root());
        // TODO: Move this to configuration file
        let ROOT_SERVERS = [
            ("a.root-servers.net", "198.41.0.4"),
            ("b.root-servers.net", "192.228.79.201"),
            ("c.root-servers.net", "192.33.4.12"),
            ("d.root-servers.net", "199.7.91.13"),
            ("e.root-servers.net", "192.203.230.10"),
            ("f.root-servers.net", "192.5.5.241"),
            ("g.root-servers.net", "192.112.36.4"),
            ("h.root-servers.net", "198.97.190.53"),
            ("i.root-servers.net", "192.36.148.17"),
            ("j.root-servers.net", "192.58.128.30"),
            ("k.root-servers.net", "193.0.14.129"),
            ("l.root-servers.net", "199.7.83.42"),
            ("m.root-servers.net", "202.12.27.33"),
        ];
        for &(domain, ip) in &ROOT_SERVERS {
            entry.add_ns(
                IpAddr::V4(ip.parse().unwrap()),
                Name::parse(domain, Some(Name::root()).as_ref()).unwrap(),
            );
        }
    }
    fn resolve_recursive(&self, q: &Query) -> Result<Message> {
        RecursiveResolver::resolve(q, self.ns_cache.clone())
    }
    pub fn resolve(&self, msg: &mut Message) -> Result<()> {
        debug_assert!(msg.get_queries().len() == 1);
        debug_assert!(msg.get_answers().is_empty());
        debug_assert!(msg.get_name_servers().is_empty());
        let entry = self.cache.lookup(msg.get_queries()[0].get_name());
        match entry.lock().unwrap().lookup(&msg.get_queries()[0].get_query_type()) {
            None => {},
            Some(cached) => {
                // TODO: Adjust TTL, check whether records are stale
                msg.copy_resp_from(cached);
                return Ok(());
            },
        };
        let resp = try!(self.resolve_recursive(&msg.get_queries()[0]));
        entry.lock().unwrap().update(&resp);
        msg.copy_resp_from(&resp);
        Ok(())
    }
}
impl Default for Resolver {
    fn default() -> Self {
        let ret = Resolver {
            cache: Default::default(),
            ns_cache: Default::default(),
        };
        ret.init_root_servers();
        ret
    }
}
