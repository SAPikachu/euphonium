use std::sync::{Arc};
use std::net::IpAddr;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicIsize, Ordering, AtomicBool};

use mioco::sync::Mutex;
use trust_dns::op::{Message, ResponseCode, Query};
use trust_dns::rr::{DNSClass, Name, RecordType, RData, Record};
use itertools::Itertools;

use utils::{Result, CloneExt, Future, AsDisplay, MessageExt};
use query::{query_multiple_handle_futures, query_with_validator};
use cache::{Cache, RecordSource};
use nscache::NsCache;
use config::Config;
use resolver::{ErrorKind, RcResolver};
use validator::{DnssecValidator, SubqueryResolver};

#[derive(Eq, PartialEq, Hash, Clone, Debug)]
struct QueryHash(Name, RecordType, DNSClass);
impl<'a> From<&'a Query> for QueryHash {
    fn from(q: &'a Query) -> Self {
        QueryHash(q.get_name().clone(), q.get_query_type(), q.get_query_class())
    }
}

#[derive(Eq, PartialEq, Hash, Clone, Debug)]
enum QueriedItem {
    NS(IpAddr),
    CNAME(Name),
    NSDomain(Name),
    Query(QueryHash),
}
struct RecursiveResolverState {
    queried_items: Mutex<HashSet<QueriedItem>>,
    query: Query,
    parent: RcResolver,
    query_limit: AtomicIsize,
    is_done: Arc<AtomicBool>,
}
impl RecursiveResolverState {
    fn new(q: &Query, parent: RcResolver) -> Self {
        let mut queried_items = HashSet::<QueriedItem>::new();
        queried_items.insert(QueriedItem::Query(q.into()));
        RecursiveResolverState {
            queried_items: Mutex::new(queried_items),
            query: q.clone(),
            parent: parent,
            query_limit: AtomicIsize::new(256),
            is_done: Arc::default(),
        }
    }
    fn new_inner(&self, q: &Query) -> Result<Self> {
        let mut queried_items = HashSet::<QueriedItem>::new();
        // Exclude NS and NSDomain, since we are querying a different domain
        queried_items.extend(
            self.queried_items.lock().unwrap().iter()
            .filter(|x| if let QueriedItem::NS(_) = **x { false } else { true })
            .filter(|x| if let QueriedItem::NSDomain(_) = **x { false } else { true })
            .map(|x| (*x).clone())
        );
        if !queried_items.insert(QueriedItem::Query(q.into())) {
            return Err(ErrorKind::AlreadyQueried.into());
        }
        Ok(RecursiveResolverState {
            queried_items: Mutex::new(queried_items),
            query: q.clone(),
            parent: self.parent.clone(),
            query_limit: AtomicIsize::new(self.query_limit.load(Ordering::Relaxed)),
            is_done: self.is_done.clone(),
        })
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
            RData::A(ref address) => Some((IpAddr::V4(*address), x.get_ttl())),
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
        let mut extra_iter = extra_futures.into_iter().peekable();
        if ns_iter.peek().is_none() && extra_iter.peek().is_none() {
            debug!("{}: No name server", self.state.query.as_disp());
            return Err(ErrorKind::NoNameserver.into());
        }
        let mut futures: Vec<_> = ns_iter
        .filter_map(|x| self.query_ns_future(&x))
        .collect();
        futures.extend(extra_iter);
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
    fn maybe_stop(&self) -> Result<()> {
        if self.state.is_done.load(Ordering::Acquire) {
            return Err(ErrorKind::LostRace.into());
        }
        Ok(())
    }
    fn query_ns(self, ns: IpAddr) -> Result<Message> {
        try!(self.maybe_stop());
        let result = try!(query_with_validator(
            self.state.query.clone(),
            ns,
            *self.get_config().query.timeout,
            &mut DnssecValidator::new(&self),
        ));
        try!(self.maybe_stop());
        if result.get_response_code() != ResponseCode::NoError {
            return Ok(result);
        }
        if !result.get_answers().is_empty() {
            return self.handle_normal_resp(result);
        }
        if result.get_name_servers().iter().any(|x| x.get_rr_type() == RecordType::SOA) {
            // Domain exists, but no record
            return Ok(result)
        }
        self.handle_ns_referral(result)
    }
    #[allow(similar_names)]
    fn find_unresolved_cnames(&self, msg: &Message) -> Option<Vec<Record>> {
        let mut name = self.state.query.get_name();
        let query_type = self.state.query.get_query_type();
        let mut unresolved_cnames = Vec::<&Record>::new();
        let trust_cname_hinting = self.get_config().query.trust_cname_hinting;
        loop {
            let cnames = {
                let matched_records = || msg.get_answers().iter()
                .filter(|x| x.get_name() == name);
                let have_real_record = matched_records()
                .any(|x| x.get_rr_type() == query_type);
                if have_real_record && trust_cname_hinting {
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
            if !trust_cname_hinting {
                break
            }
            name = match *cnames[0].get_rdata() {
                RData::CNAME(ref cname) => cname,
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
        if self.state.query.get_query_type() == RecordType::CNAME {
            // No need to resolve CNAME chain(?)
            return Ok(msg);
        }
        if let Some(unresolved_cnames) = self.find_unresolved_cnames(&msg) {
            let final_record = &unresolved_cnames[unresolved_cnames.len() - 1];
            let next_name = match *final_record.get_rdata() {
                RData::CNAME(ref cname) => cname.clone(),
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
                    warn!("Failed to resolve CNAME {} for {}: {:?}",
                          next_query.get_name(), self.state.query.as_disp(), e);
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
                    let mut new_msg = msg.without_rr();
                    unresolved_cnames.iter().cloned().foreach(|x| {
                        new_msg.add_answer(x);
                    });
                    next_msg.get_answers().iter().cloned().foreach(|x| {
                        new_msg.add_answer(x);
                    });
                    return Ok(new_msg);
                },
            };
        }
        Ok(msg)
    }
    fn handle_ns_referral(&self, msg: Message) -> Result<Message> {
        let mut ns_domains : HashMap<_, _> = msg.get_name_servers().iter()
        .filter_map(|x| match *x.get_rdata() {
            RData::NS(ref nsdname) => Some((nsdname.clone(), x.get_name().clone())),
            _ => None,
        })
        .collect();
        if ns_domains.is_empty() {
            debug!("Nameserver returned NOERROR and empty answer: {}, {}",
                   msg.get_queries()[0].as_disp(), msg.as_disp());
            return Ok(msg);
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
            RData::A(ref address) => Some((
                IpAddr::V4(*address), x.get_name().clone(), x.get_ttl(),
            )),
            RData::AAAA(ref address) => Some((
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
    pub fn resolve(q: &Query, parent: RcResolver) -> Result<Message> {
        let resolver = RecursiveResolver {
            state: Arc::new(RecursiveResolverState::new(q, parent)),
        };
        let ret = try!(resolver.query());
        resolver.state.is_done.store(true, Ordering::Release);
        resolver.update_cache(&ret);
        Ok(ret)
    }
    fn resolve_next(&self, q: &Query) -> Result<Message> {
        if let Some(msg) = self.get_cache().lookup(q, |m| m.create_response()) {
            return Ok(msg);
        }
        let resolver = RecursiveResolver {
            state: Arc::new(try!(self.state.new_inner(q))),
        };
        let ret = try!(resolver.query());
        self.update_cache(&ret);
        Ok(ret)
    }
}
impl<'a> SubqueryResolver for &'a RecursiveResolver {
    fn resolve_sub(&self, q: Query) -> Result<Message> {
        self.resolve_next(&q)
    }
}
