use std::sync::Arc;
use std::net::IpAddr;
use std::collections::{HashMap, HashSet};
use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::default::Default;
use std::str::FromStr;
use std::sync::atomic::{AtomicIsize, Ordering};

use mioco::mio::Ipv4Addr;
use mioco::sync::Mutex;
use trust_dns::op::{Message, ResponseCode, Edns, OpCode, Query};
use trust_dns::rr::{DNSClass, Name, RecordType, RData, Record};
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
    /// Another coroutine is already working on the query
    LostRace,
}
pub struct Resolver {
    cache: Cache,
    ns_cache: RcNsCache,
}
pub type RcResolver = Arc<Resolver>;

#[derive(Eq, PartialEq, Hash, Clone)]
enum QueriedItem {
    NS(IpAddr),
    CNAME(Name),
}
struct RecursiveResolverState {
    queried_items: Mutex<HashSet<QueriedItem>>,
    query: Query,
    ns_cache: RcNsCache,
    query_limit: AtomicIsize,
}
impl RecursiveResolverState {
    fn new(q: &Query, ns_cache: RcNsCache) -> Self {
        RecursiveResolverState {
            queried_items: Mutex::new(Default::default()),
            query: q.clone(),
            ns_cache: ns_cache,
            query_limit: AtomicIsize::new(256),
        }
    }
    fn new_inner(&self, q: &Query) -> Self {
        RecursiveResolverState {
            queried_items: Mutex::new(Default::default()),
            query: q.clone(),
            ns_cache: self.ns_cache.clone(),
            query_limit: AtomicIsize::new(self.query_limit.load(Ordering::Relaxed)),
        }
    }
}
#[derive(Clone)]
struct RecursiveResolver {
    state: Arc<RecursiveResolverState>,
}
impl RecursiveResolver {
    fn query(&self) -> Result<Message> {
        // TODO: Handle expiration
        let ns = self.state.ns_cache.lookup_recursive(&self.state.query.get_name());
        self.query_ns_multiple(&ns)
    }
    fn query_ns_multiple(&self, ns: &[IpAddr]) -> Result<Message> {
        if ns.is_empty() {
            return Err(ErrorKind::NoNameserver.into());
        }
        let mut futures: Vec<_> = ns.iter().filter_map(|x| self.query_ns_future(x)).collect();
        if futures.is_empty() {
            return Err(ErrorKind::LostRace.into());
        }
        query_multiple_handle_futures(&mut futures)
    }
    fn register_query(&self, item: QueriedItem) -> bool {
        let mut guard = self.state.queried_items.lock().unwrap();
        if guard.contains(&item) {
            return false;
        }
        if self.state.query_limit.fetch_sub(1, Ordering::Relaxed) <= 0 {
            debug_assert!(false);
            warn!("Already queried too many servers for {:?}, bug or attack?", self.state.query);
            return false;
        }
        guard.insert(item);
        true
    }
    fn query_ns_future(&self, ns: &IpAddr) -> Option<Future<Result<Message>>> {
        if !self.register_query(QueriedItem::NS(*ns)) {
            return None;
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
            return self.handle_normal_resp(result);
        }
        self.handle_ns_referral(&result)
    }
    #[allow(similar_names)]
    fn find_unresolved_cnames(&self, msg: &Message) -> Option<Vec<Record>> {
        let mut name = self.state.query.get_name();
        let query_type = self.state.query.get_query_type();
        let mut unresolved_cnames = Vec::<&Record>::new();
        loop {
            let cnames = {
                let matched_records = || msg.get_answers().iter()
                .filter(|x| x.get_name() == name);
                let have_real_record = matched_records()
                .any(|x| x.get_rr_type() == query_type);
                if have_real_record {
                    return None;
                }
                matched_records().filter(|x| x.get_rr_type() == RecordType::CNAME)
                .collect_vec()
            };
            if cnames.is_empty() {
                break;
            }
            if cnames.len() > 1 {
                debug_assert!(false);
                warn!("Server returned multiple CNAMEs for a single domain");
                // Try to resolve anyways
            }
            unresolved_cnames.push(cnames[0]);
            name = match *cnames[0].get_rdata() {
                RData::CNAME {ref cname} => cname,
                _ => panic!("Record type doesn't match RData"),
            };
        }
        if unresolved_cnames.is_empty() {
            // FIXME: This means the message has unrelated records in answer section?
            return None;
        }
        Some(unresolved_cnames.iter().map(|x| (*x).clone()).collect())
    }
    #[allow(similar_names)]
    fn handle_normal_resp(&self, msg: Message) -> Result<Message> {
        // TODO: Update main cache if this response is more preferable
        // TODO: Anything else to do?
        if self.state.query.get_query_type() == RecordType::CNAME {
            // No need to resolve CNAME chain(?)
            return Ok(msg);
        }
        if let Some(unresolved_cnames) = self.find_unresolved_cnames(&msg) {
            let final_record = &unresolved_cnames[unresolved_cnames.len() - 1];
            let next_name = match *final_record.get_rdata() {
                RData::CNAME {ref cname} => cname.clone(),
                _ => panic!("Record type doesn't match RData"),
            };
            if !self.register_query(QueriedItem::CNAME(next_name.clone())) {
                return Err(ErrorKind::LostRace.into());
            }
            debug!("[{}] CNAME referral: {}", self.state.query.get_name(), next_name);
            let mut next_query = self.state.query.clone();
            next_query.name(next_name);
            match self.resolve_next(&next_query) {
                Err(_) => { return Ok(msg); },
                Ok(ref next_msg) if
                    next_msg.get_response_code() != ResponseCode::NoError
                => {
                    return Ok(msg);
                }
                Ok(next_msg) => {
                    // Simpler way to clear all answers
                    let mut new_msg = msg.truncate();
                    assert!(new_msg.get_queries().is_empty());
                    assert!(new_msg.get_answers().is_empty());
                    assert!(new_msg.get_name_servers().is_empty());
                    assert!(new_msg.get_additional().is_empty());
                    new_msg.truncated(false);
                    new_msg.add_query(self.state.query.clone());
                    unresolved_cnames.iter().cloned().foreach(|x| {
                        new_msg.add_answer(x);
                    });
                    new_msg.add_all_answers(next_msg.get_answers());
                    return Ok(new_msg);
                },
            };
        }
        Ok(msg)
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
        if !referred_zone.zone_of(self.state.query.get_name()) {
            warn!("Nameserver returned NS records for incorrect zone");
            return Err(ErrorKind::InsaneNsReferral.into());
        }
        debug!("[{}] NS referral: {}", self.state.query.get_name(), referred_zone);

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
    fn resolve_next(&self, q: &Query) -> Result<Message> {
        let resolver = RecursiveResolver {
            state: Arc::new(self.state.new_inner(q)),
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
