use std::sync::{Arc};
use std::net::IpAddr;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicIsize, Ordering, AtomicBool};

use mioco::sync::Mutex;
use mioco::sync::mpsc::{channel, Sender};
use trust_dns::op::{Message, ResponseCode, Query};
use trust_dns::rr::{DNSClass, Name, RecordType, RData, Record};
use itertools::Itertools;

use utils::{Result, Future, AsDisplay, MessageExt};
use query::{query_multiple_handle_futures, query_with_validator};
use cache::{Cache, RecordSource};
use nscache::NsCache;
use config::Config;
use resolver::{ErrorKind, RcResolver};
use validator::{DnssecValidator, SubqueryResolver, DummyValidator};

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
enum SubqueryState {
    // Wraps a sender to send result when the query is completed. Intended for chained
    // notification.
    Pending(Option<Sender<Option<Message>>>),
    Completed(Message),
    Error,
}
struct RecursiveResolverState {
    queried_items: Mutex<HashSet<QueriedItem>>,
    query: Query,
    parent: RcResolver,
    query_limit: AtomicIsize,
    is_done: Arc<AtomicBool>,
    subqueries: Arc<Mutex<HashMap<QueryHash, SubqueryState>>>,
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
            subqueries: Arc::new(Mutex::new(Default::default())),
        }
    }
    fn new_inner(&self, q: &Query) -> Result<Self> {
        let queried_items = {
            let guard = self.queried_items.lock().unwrap();
            let mut items = HashSet::<QueriedItem>::new();
            // Exclude NS and NSDomain, since we are querying a different domain
            items.extend(
                guard.iter()
                .filter(|x| if let QueriedItem::NS(_) = **x { false } else { true })
                .filter(|x| if let QueriedItem::NSDomain(_) = **x { false } else { true })
                .map(|x| (*x).clone())
            );
            if !items.insert(QueriedItem::Query(q.into())) {
                return Err(ErrorKind::AlreadyQueried.into());
            }
            items
        };
        Ok(RecursiveResolverState {
            queried_items: Mutex::new(queried_items),
            query: q.clone(),
            parent: self.parent.clone(),
            query_limit: AtomicIsize::new(self.query_limit.load(Ordering::Relaxed)),
            is_done: self.is_done.clone(),
            subqueries: self.subqueries.clone(),
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
        let name = self.state.query.get_name();
        let is_ds = self.state.query.get_query_type() == RecordType::DS && !name.is_root();
        let nscache = self.get_ns_cache();
        let ns = if is_ds {
            // Start from the first ancestor zone that is known to serve DS response, which
            // ensures not to be the same zone as `name`
            nscache.lookup_recursive_with_filter(&name.base_name(), |ent| {
                let mut q = self.state.query.clone();
                q.name(ent.get_zone().clone());
                self.get_cache().lookup(&q, |ent| ent.is_authenticated()).unwrap_or(false)
            })
        } else {
            nscache.lookup_recursive(name)
        };
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
    fn query_ns_impl(&self, ns: IpAddr) -> Result<Message> {
        let enable_dnssec = self.get_config().query.enable_dnssec;
        if enable_dnssec {
            query_with_validator(
                self.state.query.clone(),
                ns,
                *self.get_config().query.timeout,
                &mut DnssecValidator::new(self),
            )
        } else {
            query_with_validator(
                self.state.query.clone(),
                ns,
                *self.get_config().query.timeout,
                &mut DummyValidator,
            )
        }
    }
    fn query_ns(self, ns: IpAddr) -> Result<Message> {
        try!(self.maybe_stop());
        let result = try!(self.query_ns_impl(ns));
        try!(self.maybe_stop());
        if result.get_response_code() == ResponseCode::NXDomain &&
            result.get_answers().len() == 1 &&
            result.get_answers()[0].get_rr_type() == RecordType::CNAME
        {
            // https://serverfault.com/questions/157775/can-a-valid-cname-response-contain-an-nxdomain-status
            return self.handle_normal_resp(result);
        }
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
                Ok(next_msg) => {
                    let mut new_msg = msg.without_rr();
                    new_msg.response_code(next_msg.get_response_code());
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
        use std::collections::hash_map::Entry::{Occupied, Vacant};
        use ::recursive::SubqueryState::{Pending, Completed, Error};
        if let Some(Some(msg)) = self.get_cache().lookup(
            q,
            |m| if m.get_source() >= RecordSource::Recursive {
                Some(m.create_response())
            } else {
                None
            },
        ) {
            return Ok(msg);
        }
        try!(self.maybe_stop());
        if *q == self.state.query {
            return Err(ErrorKind::AlreadyQueried.into());
        }
        if self.state.queried_items.lock().unwrap().contains(&QueriedItem::Query(q.into())) {
            // Avoid query loop which causes resource leak
            return Err(ErrorKind::AlreadyQueried.into());
        }
        let (send, recv) = {
            use std::mem;
            match self.state.subqueries.lock().unwrap().entry(q.into()) {
                Vacant(e) => {
                    debug!("Subquery (new): {} -> {}",
                           self.state.query.as_disp(), q.as_disp());
                    e.insert(Pending(None));
                    (None, None)
                },
                Occupied(mut e) => {
                    match *e.get_mut() {
                        Completed(ref msg) => return Ok(msg.clone()),
                        Error => return Err(ErrorKind::AlreadyQueried.into()),
                        Pending(ref mut stored_sender) => {
                            debug!("Subquery (existing): {} -> {}",
                                   self.state.query.as_disp(), q.as_disp());
                            let (send, recv) = channel::<Option<Message>>();
                            let mut send_opt = Some(send);
                            mem::swap(stored_sender, &mut send_opt);
                            (send_opt, Some(recv))
                        }
                    }
                },
            }
        };
        match recv {
            Some(ref r) => {
                let ret = r.recv();
                let result = match ret {
                    Ok(Some(msg)) => Ok(msg),
                    Ok(None) => Err(ErrorKind::AlreadyQueried.into()),
                    Err(e) => Err(e.into()),
                };
                if let Some(ref s) = send {
                    s.send(result.as_ref().map(|x| x.clone()).ok()).is_ok();
                }
                result
            },
            None => {
                assert!(send.is_none());
                let ret = self.resolve_next_impl(q);
                match self.state.subqueries.lock().unwrap().entry(q.into()) {
                    Vacant(_) => {
                        panic!("Who changed this to Vacant again?");
                    },
                    Occupied(mut e) => {
                        if let Pending(Some(ref sender)) = *e.get() {
                            sender.send(ret.as_ref().map(|x| x.clone()).ok()).is_ok();
                        }
                        e.insert(match ret {
                            Ok(ref msg) => Completed(msg.clone()),
                            Err(_) => Error,
                        })
                    },
                };
                ret
            },
        }
    }
    fn resolve_next_impl(&self, q: &Query) -> Result<Message> {
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
