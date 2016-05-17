use std::sync::{Arc};
use std::net::IpAddr;
use std::collections::{HashMap, HashSet};
use std::default::Default;
use std::sync::atomic::{AtomicIsize, Ordering};

use mioco::sync::Mutex;
use trust_dns::op::{Message, ResponseCode, Query};
use trust_dns::rr::{DNSClass, Name, RecordType, RData, Record};
use itertools::Itertools;

use utils::{Result, CloneExt, MessageExt, Future};
use query::{query_multiple_handle_futures, query as query_one};
use cache::{Cache, RecordSource};
use nscache::NsCache;
use config::Config;
use resolver::{ErrorKind, RcResolver};

#[derive(Eq, PartialEq, Hash, Clone, Debug)]
enum QueriedItem {
    NS(IpAddr),
    CNAME(Name),
    NSDomain(Name),
}
struct RecursiveResolverState {
    queried_items: Mutex<HashSet<QueriedItem>>,
    query: Query,
    parent: RcResolver,
    query_limit: AtomicIsize,
    skip_cache: bool,
}
impl RecursiveResolverState {
    fn new(q: &Query, parent: RcResolver, skip_cache: bool) -> Self {
        RecursiveResolverState {
            queried_items: Mutex::new(Default::default()),
            query: q.clone(),
            parent: parent,
            query_limit: AtomicIsize::new(256),
            skip_cache: skip_cache,
        }
    }
    fn new_inner(&self, q: &Query) -> Self {
        RecursiveResolverState {
            queried_items: Mutex::new(Default::default()),
            query: q.clone(),
            parent: self.parent.clone(),
            query_limit: AtomicIsize::new(self.query_limit.load(Ordering::Relaxed)),
            skip_cache: self.skip_cache,
        }
    }
}
#[derive(Clone)]
pub struct RecursiveResolver {
    state: Arc<RecursiveResolverState>,
}
impl RecursiveResolver {
    fn get_cache(&self) -> &Cache {
        &self.state.parent.cache
    }
    fn get_ns_cache(&self) -> &NsCache {
        &self.state.parent.ns_cache
    }
    fn get_config(&self) -> &Config {
        &self.state.parent.config
    }
    fn query(&self) -> Result<Message> {
        // TODO: Handle expiration
        let ns = self.get_ns_cache().lookup_recursive(self.state.query.get_name());
        self.query_ns_multiple(ns, None)
    }
    fn query_ns_domain(&self, auth_zone: &Name, ns: &Name) -> Result<Message> {
        debug!("Querying IP of NS {} in zone {}", ns, auth_zone);
        let mut query = Query::new();
        query.name(ns.clone())
        .query_type(RecordType::A)
        .query_class(DNSClass::IN);
        // TODO: IPv6
        let result = try!(self.resolve_next(&query));
        let ips = result.get_answers().iter().filter_map(|x| match *x.get_rdata() {
            RData::A {ref address} => Some((IpAddr::V4(*address), x.get_ttl())),
            _ => None,
        }).collect_vec();
        self.get_ns_cache().update(auth_zone, ips.iter().map(|&(ip, ttl)| (ip, ns.clone(), ttl as u64)));
        self.query_ns_multiple(ips.iter().map(|&(ip, _)| ip), None)
    }
    fn query_ns_domain_future(&self, auth_zone: &Name, ns: Name) -> Option<Future<Result<Message>>> {
        if !self.register_query(QueriedItem::NSDomain(ns.clone())) {
            return None;
        }
        let inst = self.clone();
        let auth_zone_clone = auth_zone.clone();
        Some(Future::from_fn(move || inst.query_ns_domain(&auth_zone_clone, &ns)))
    }
    fn query_ns_domain_futures<T>(&self, auth_zone: &Name, ns_iter: T) -> Vec<Future<Result<Message>>> where T: IntoIterator<Item=Name> {
        ns_iter.into_iter()
        .filter_map(|x| self.query_ns_domain_future(auth_zone, x))
        .collect()
    }
    fn query_ns_multiple<TNs, TExtra>(&self, ns: TNs, extra_futures: TExtra) -> Result<Message>
        where TNs: IntoIterator<Item=IpAddr>,
              TExtra: IntoIterator<Item=Future<Result<Message>>>,
    {
        let mut ns_iter = ns.into_iter().peekable();
        if ns_iter.peek().is_none() {
            return Err(ErrorKind::NoNameserver.into());
        }
        let mut futures: Vec<_> = ns_iter
        .filter_map(|x| self.query_ns_future(&x))
        .collect();
        futures.extend(extra_futures);
        if futures.is_empty() {
            return Err(ErrorKind::LostRace.into());
        }
        query_multiple_handle_futures(&mut futures)
    }
    fn register_query(&self, item: QueriedItem) -> bool {
        let mut guard = self.state.queried_items.lock().unwrap();
        if guard.contains(&item) {
            trace!("Already queried {:?}", item);
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
        let result = try!(query_one(self.state.query.clone(), ns, *self.get_config().query.timeout));
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
                Err(e) => {
                    warn!("Failed to resolve CNAME {}: {:?}", next_query.get_name(), e);
                    return Ok(msg);
                },
                Ok(ref next_msg) if
                    next_msg.get_response_code() != ResponseCode::NoError
                => {
                    warn!("Failed to resolve CNAME {}: Server returned error: {:?}",
                          next_query.get_name(), next_msg.get_response_code());
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
            RData::A {ref address} => Some((
                IpAddr::V4(*address), x.get_name().clone(), x.get_ttl(),
            )),
            RData::AAAA {ref address} => Some((
                IpAddr::V6(*address), x.get_name().clone(), x.get_ttl(),
            )),
            _ => None,
        })
        .collect();
        self.get_ns_cache().update(
            &referred_zone,
            ns_items.iter().map(|&(ip, ref name, ttl)| {
                ns_domains.remove(name);
                (ip, name.clone(), ttl as u64)
            }),
        );
        let orphan_domain_futures = self.query_ns_domain_futures(
            &referred_zone, ns_domains.keys().cloned(),
        );
        self.query_ns_multiple(
            ns_items.iter().map(|x| x.0),
            orphan_domain_futures,
        )
    }
    fn update_cache(&self, msg: &Message) {
        self.get_cache().update_from_message(msg, RecordSource::Recursive);
    }
    pub fn resolve(q: &Query, parent: RcResolver, skip_cache: bool) -> Result<Message> {
        let resolver = RecursiveResolver {
            state: Arc::new(RecursiveResolverState::new(q, parent, skip_cache)),
        };
        let ret = try!(resolver.query());
        resolver.update_cache(&ret);
        Ok(ret)
    }
    fn resolve_next(&self, q: &Query) -> Result<Message> {
        if !self.state.skip_cache {
            if let Some(msg) = self.get_cache().lookup_with_type(
                q.get_name(), q.get_query_type(), |m| m.clone_resp_for(q),
            ) {
                return Ok(msg);
            }
        }
        let resolver = RecursiveResolver {
            state: Arc::new(self.state.new_inner(q)),
        };
        let ret = try!(resolver.query());
        self.update_cache(&ret);
        Ok(ret)
    }
}