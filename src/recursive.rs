use std::sync::{Arc};
use std::net::IpAddr;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{Ordering, AtomicBool, AtomicUsize, ATOMIC_USIZE_INIT};

use mioco::sync::Mutex;
use mioco::sync::mpsc::{channel, Sender};
use trust_dns::op::{Message, ResponseCode, Query};
use trust_dns::rr::{DNSClass, Name, RecordType, RData, Record};
use trust_dns_proto::rr::dnssec::rdata::DNSSECRecordType;
use itertools::Itertools;

use utils::{Result, Error, Future, AsDisplay, MessageExt};
use query::{query_multiple_handle_futures, query_with_validator};
use cache::{Cache, RecordSource};
use nscache::NsCache;
use config::Config;
use resolver::{ErrorKind, RcResolver};
use validator::{DnssecValidator, SubqueryResolver, DummyValidator};

static _DEBUG_ID: AtomicUsize = ATOMIC_USIZE_INIT;

#[derive(Eq, PartialEq, Hash, Clone, Debug)]
struct QueryHash(Name, RecordType, DNSClass);
impl<'a> From<&'a Query> for QueryHash {
    fn from(q: &'a Query) -> Self {
        QueryHash(q.name().clone(), q.query_type(), q.query_class())
    }
}

#[derive(Eq, PartialEq, Hash, Clone, Debug)]
enum QueriedItem {
    NS(QueryHash, IpAddr),
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
    queried_items: Arc<Mutex<HashSet<QueriedItem>>>,
    query: Query,
    parent: RcResolver,
    is_done: Arc<AtomicBool>,
    subqueries: Arc<Mutex<HashMap<QueryHash, SubqueryState>>>,
    upstream_queries: HashSet<QueryHash>,
}
impl RecursiveResolverState {
    fn new(q: &Query, parent: RcResolver) -> Self {
        let mut queried_items = HashSet::<QueriedItem>::new();
        queried_items.insert(QueriedItem::Query(q.into()));
        RecursiveResolverState {
            queried_items: Arc::new(Mutex::new(queried_items)),
            query: q.clone(),
            parent: parent,
            is_done: Arc::default(),
            subqueries: Arc::new(Mutex::new(Default::default())),
            upstream_queries: HashSet::default(),
        }
    }
    fn new_inner(&self, q: &Query) -> Result<Self> {
        let mut upstream_queries = self.upstream_queries.clone();
        upstream_queries.insert((&self.query).into());
        Ok(RecursiveResolverState {
            queried_items: self.queried_items.clone(),
            query: q.clone(),
            parent: self.parent.clone(),
            is_done: self.is_done.clone(),
            subqueries: self.subqueries.clone(),
            upstream_queries: upstream_queries,
        })
    }
}
#[derive(Clone)]
pub struct RecursiveResolver {
    is_root: bool,
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
        let name = self.state.query.name();
        let is_ds = self.state.query.query_type() == RecordType::DNSSEC(DNSSECRecordType::DS) && !name.is_root();
        let nscache = self.get_ns_cache();
        let ns = if is_ds {
            // Start from the first ancestor zone that is known to serve DS response, which
            // ensures not to be the same zone as `name`
            nscache.lookup_recursive_with_filter(&name.base_name(), |ent| {
                let mut q = self.state.query.clone();
                q.set_name(ent.get_zone().clone());
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
        query.set_name(ns.clone())
        .set_query_type(RecordType::A)
        .set_query_class(DNSClass::IN);
        // TODO: IPv6
        self.maybe_stop()?;
        let result = try!(self.resolve_next(&query));
        let ips = result.answers().iter().filter_map(|x| match *x.rdata() {
            RData::A(ref address) => Some((IpAddr::V4(*address), x.ttl())),
            _ => None,
        }).collect_vec();
        self.get_ns_cache().update(auth_zone, ips.iter().map(|&(ip, ttl)| (ip, ns.clone(), ttl as u64)));
        self.maybe_stop()?;
        self.query_ns_multiple(ips.iter().map(|&(ip, _)| ip), None)
    }
    fn query_ns_domain_future(&self, auth_zone: &Name, ns: Name) -> Option<Future<Result<Message>>> {
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
        if guard.len() >= 2048 {
            debug_assert!(false);
            warn!("Already queried too many servers for {:?}, bug or attack?", self.state.query);
            warn!("Queried items: {}", guard.iter().map(|x| format!("{:?}", x)).collect_vec().join(", "));
            return false;
        }
        trace!("register_query: {:?}", item);
        guard.insert(item);
        true
    }
    fn query_ns_future(&self, ns: &IpAddr) -> Option<Future<Result<Message>>> {
        if !self.register_query(QueriedItem::NS((&self.state.query).into(), *ns)) {
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
        (|| {
            if result.response_code() == ResponseCode::NXDomain &&
                result.answers().len() == 1 &&
                result.answers()[0].rr_type() == RecordType::CNAME
            {
                // https://serverfault.com/questions/157775/can-a-valid-cname-response-contain-an-nxdomain-status
                return self.handle_normal_resp(result);
            }
            if result.response_code() != ResponseCode::NoError {
                return Ok(result);
            }
            if !result.answers().is_empty() {
                return self.handle_normal_resp(result);
            }
            if result.name_servers().iter().any(|x| x.rr_type() == RecordType::SOA) {
                // Domain exists, but no record
                return Ok(result)
            }
            self.handle_ns_referral(result)
        })().map(|msg| { self.update_cache(&msg); msg })
    }
    #[allow(similar_names)]
    fn find_unresolved_cnames(&self, msg: &Message) -> Option<Vec<Record>> {
        let mut name = self.state.query.name();
        let query_type = self.state.query.query_type();
        let mut unresolved_cnames = Vec::<&Record>::new();
        let trust_cname_hinting = self.get_config().query.trust_cname_hinting;
        loop {
            let cnames = {
                let matched_records = || msg.answers().iter()
                .filter(|x| x.name() == name);
                let have_real_record = matched_records()
                .any(|x| x.rr_type() == query_type);
                if have_real_record && trust_cname_hinting {
                    return None;
                }
                matched_records().filter(|x| x.rr_type() == RecordType::CNAME)
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
            name = match *cnames[0].rdata() {
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
        if self.state.query.query_type() == RecordType::CNAME {
            // No need to resolve CNAME chain(?)
            return Ok(msg);
        }
        if let Some(unresolved_cnames) = self.find_unresolved_cnames(&msg) {
            let final_record = &unresolved_cnames[unresolved_cnames.len() - 1];
            let next_name = match *final_record.rdata() {
                RData::CNAME(ref cname) => cname.clone(),
                _ => panic!("Record type doesn't match RData"),
            };
            debug!("[{}] CNAME referral: {}", self.state.query.name(), next_name);
            let mut next_query = self.state.query.clone();
            next_query.set_name(next_name);
            match self.resolve_next(&next_query) {
                Err(Error::Resolver(ErrorKind::AlreadyQueried)) => {
                    return Err(Error::Resolver(ErrorKind::AlreadyQueried));
                },
                Err(Error::Resolver(ErrorKind::LostRace)) => {
                    return Err(Error::Resolver(ErrorKind::LostRace));
                },
                Err(e) => {
                    self.maybe_stop()?;
                    warn!("Failed to resolve CNAME {} for {}: {:?}",
                          next_query.name(), self.state.query.as_disp(), e);
                    return Ok(msg);
                },
                Ok(next_msg) => {
                    self.maybe_stop()?;
                    let mut new_msg = msg.without_rr();
                    new_msg.set_response_code(next_msg.response_code());
                    unresolved_cnames.iter().cloned().foreach(|x| {
                        new_msg.add_answer(x);
                    });
                    next_msg.answers().iter().cloned().foreach(|x| {
                        new_msg.add_answer(x);
                    });
                    return Ok(new_msg);
                },
            };
        }
        Ok(msg)
    }
    fn handle_ns_referral(&self, msg: Message) -> Result<Message> {
        let mut ns_domains : HashMap<_, _> = msg.name_servers().iter()
        .filter_map(|x| match *x.rdata() {
            RData::NS(ref nsdname) => Some((nsdname.clone(), x.name().clone())),
            _ => None,
        })
        .collect();
        if ns_domains.is_empty() {
            debug!("Nameserver returned NOERROR and empty answer: {}, {}",
                   msg.queries()[0].as_disp(), msg.as_disp());
            return Ok(msg);
        }
        if ns_domains.values().dedup().count() > 1 {
            // FIXME: Is this legal?
            debug_assert!(false);
            warn!("Nameserver returned NS records for multiple zones");
            return Err(ErrorKind::InsaneNsReferral.into());
        }
        let referred_zone = ns_domains.values().next().unwrap().clone();
        if !referred_zone.zone_of(self.state.query.name()) {
            warn!("Nameserver returned NS records for incorrect zone");
            return Err(ErrorKind::InsaneNsReferral.into());
        }
        debug!("[{}] NS referral: {}", self.state.query.name(), referred_zone);

        // Get IPs of all NSes.
        let ns_items: Vec<_> = msg.additionals().iter()
        .filter(|x| ns_domains.contains_key(x.name()))
        .filter_map(|x| match *x.rdata() {
            RData::A(ref address) => Some((
                IpAddr::V4(*address), x.name().clone(), x.ttl(),
            )),
            RData::AAAA(ref address) => Some((
                IpAddr::V6(*address), x.name().clone(), x.ttl(),
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
        let got_best_cache = self.get_cache().update_from_message(msg, RecordSource::Recursive);
        if got_best_cache && self.is_root {
            self.state.is_done.store(true, Ordering::Release);
        }
    }
    pub fn resolve(q: &Query, parent: RcResolver) -> Result<Message> {
        let resolver = RecursiveResolver {
            is_root: true,
            state: Arc::new(RecursiveResolverState::new(q, parent)),
        };
        let ret = try!(resolver.query());
        Ok(ret)
    }
    fn resolve_from_cache(&self, q: &Query) -> Option<Message> {
        match self.get_cache().lookup(
            q,
            |m| if m.get_source() >= RecordSource::Recursive {
                Some(m.create_response())
            } else {
                None
            },
        ) {
            Some(x) => x,
            None => None,
        }
    }
    fn resolve_next(&self, q: &Query) -> Result<Message> {
        use std::collections::hash_map::Entry::{Occupied, Vacant};
        use ::recursive::SubqueryState::{Pending, Completed, Error};
        if let Some(msg) = self.resolve_from_cache(q) {
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
        let query_id = _DEBUG_ID.fetch_add(1, Ordering::Relaxed);
        let mut is_cyclic = false;
        let (send, recv) = {
            use std::mem;
            match self.state.subqueries.lock().unwrap().entry(q.into()) {
                Vacant(e) => {
                    debug!("[{}] Subquery (new): {} -> {}",
                           query_id, self.state.query.as_disp(), q.as_disp());
                    e.insert(Pending(None));
                    (None, None)
                },
                Occupied(mut e) => {
                    match *e.get_mut() {
                        Completed(ref msg) => return Ok(msg.clone()),
                        Error => return Err(ErrorKind::AlreadyQueried.into()),
                        Pending(ref mut stored_sender) => {
                            if self.state.upstream_queries.contains(&q.into()) {
                                is_cyclic = true;
                                (None, None)
                            } else {
                                debug!("[{}] Subquery (existing): {} -> {}",
                                       query_id, self.state.query.as_disp(), q.as_disp());
                                let (send, recv) = channel::<Option<Message>>();
                                let mut send_opt = Some(send);
                                mem::swap(stored_sender, &mut send_opt);
                                (send_opt, Some(recv))
                            }
                        }
                    }
                },
            }
        };
        if is_cyclic {
            use mioco::timer::Timer;
            let mut t = Timer::default();
            t.set_timeout(5000);
            t.read();
            if let Some(msg) = self.resolve_from_cache(q) {
                debug!("[{}] Subquery (breaking cycle, from cache): {} -> {}",
                query_id, self.state.query.as_disp(), q.as_disp());
                return Ok(msg);
            }
            debug!("[{}] Subquery (breaking cycle): {} -> {}",
                   query_id, self.state.query.as_disp(), q.as_disp());
            return Err(ErrorKind::AlreadyQueried.into());
        }
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
                debug!("[{}] Subquery (existing, {}) returning (OK: {})", query_id, q.as_disp(), result.is_ok());
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
                debug!("[{}] Subquery (new, {}) returning (OK: {})", query_id, q.as_disp(), ret.is_ok());
                ret
            },
        }
    }
    fn resolve_next_impl(&self, q: &Query) -> Result<Message> {
        let resolver = RecursiveResolver {
            is_root: false,
            state: Arc::new(try!(self.state.new_inner(q))),
        };
        let ret = try!(resolver.query());
        Ok(ret)
    }
}
impl<'a> SubqueryResolver for &'a RecursiveResolver {
    fn resolve_sub(&self, q: Query) -> Result<Message> {
        match self.resolve_next(&q) {
            val @ Err(Error::Resolver(ErrorKind::LostRace)) |
            val @ Err(Error::Resolver(ErrorKind::AlreadyQueried)) => {
                match self.resolve_from_cache(&q) {
                    Some(x) => Ok(x),
                    None => val,
                }
            },
            x => x,
        }
    }
}
