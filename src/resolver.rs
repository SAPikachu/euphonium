use std::collections::HashMap;
use std::default::Default;
use std::net::SocketAddr;
use std::ops::Deref;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::TryRecvError;
use std::sync::{Arc, Weak};

use itertools::Itertools;
use mioco;
use mioco::sync::mpsc::{channel, Receiver};
use mioco::sync::Mutex;
use mioco::timer::Timer;
use trust_dns_proto::op::{Message, MessageType, Query, ResponseCode};
use trust_dns_proto::rr::{Name, RData, RecordType};

use crate::cache::{Cache, RecordSource};
use crate::config::Config;
use crate::control::{ControlResult, ControlServer, Error as ControlError};
use crate::forwarding::ForwardingResolver;
use crate::nscache::NsCache;
use crate::query::{query, query_multiple_handle_futures};
use crate::recursive::RecursiveResolver;
use crate::utils::{AsDisplay, Future, MessageExt, Result};

// Idea: Use DNSSEC to check whether a domain is poisoned by GFW

#[derive(Debug, Clone)]
pub enum ErrorKind {
    NoNameserver,
    EmptyAnswer,
    InsaneNsReferral,
    /// Another coroutine is already working on the query
    LostRace,
    RejectedIp,
    AlreadyQueried,
}
enum ZoneHandler {
    Forward(SocketAddr),
    Local(Name),
}
impl ZoneHandler {
    pub fn handle(&self, msg: &mut Message, resolver: &RcResolver) -> Result<()> {
        use self::ZoneHandler::*;
        let mut q = msg.queries()[0].clone();
        match *self {
            Forward(ref server) => query(q, *server, *resolver.config.query.timeout).map(|x| {
                msg.copy_resp_from(&x);
            }),
            Local(ref zone) => {
                let query_name = q.name().clone();
                q.set_name(zone.clone());
                if resolver
                    .cache
                    .lookup(&q, |entry| {
                        entry.fill_response(msg);
                        for mut rec in msg.take_answers() {
                            if rec.name() == zone {
                                rec.set_name(query_name.clone());
                            }
                            msg.add_answer(rec);
                        }
                    })
                    .is_some()
                {
                    return Ok(());
                }
                q.set_query_type(RecordType::SOA);
                resolver.cache.lookup(&q, |entry| {
                    entry.fill_response(msg);
                    let answers = msg.take_answers();
                    msg.insert_name_servers(answers);
                });
                msg.set_response_code(ResponseCode::NXDomain);
                Ok(())
            }
        }
    }
}
pub struct Resolver {
    pub cache: Cache,
    pub ns_cache: NsCache,
    pub config: Arc<Config>,
    forwarders: Vec<Arc<ForwardingResolver>>,
    zone_handlers: HashMap<Name, ZoneHandler>,
    version: usize,
}
struct ResolverGlobal {
    current: Arc<Resolver>,
    control_server: ControlServer,
    current_version: Arc<AtomicUsize>,
}
pub struct RcResolverInner {
    resolver: Arc<Resolver>,
    global: Arc<Mutex<ResolverGlobal>>,
    current_version: Arc<AtomicUsize>,
}
impl Deref for RcResolverInner {
    type Target = Resolver;
    fn deref(&self) -> &Resolver {
        self.resolver.deref()
    }
}
macro_attr! {
    #[derive(Clone, NewtypeFrom!, NewtypeDeref!)]
    pub struct RcResolver(Arc<RcResolverInner>);
}
macro_attr! {
    #[derive(Clone, NewtypeFrom!)]
    pub struct Keepalive(Arc<Mutex<ResolverGlobal>>);
}
#[derive(Clone)]
pub struct RcResolverWeak(Weak<RcResolverInner>, Weak<Mutex<ResolverGlobal>>);

impl RcResolver {
    pub fn new(config: Config) -> Self {
        let forwarders = ForwardingResolver::create_all(&config);
        let zone_handlers = Self::init_zone_handlers(&config);
        let (send, recv) = channel::<Query>();
        let config_rc = Arc::new(config);
        let resolver = Arc::new(Resolver {
            cache: Cache::new(send, config_rc.clone()),
            ns_cache: NsCache::new(config_rc.clone()),
            config: config_rc.clone(),
            forwarders: forwarders,
            zone_handlers: zone_handlers,
            version: 0,
        });
        let current_version = Arc::new(AtomicUsize::new(0));
        let ret = RcResolver(Arc::new(RcResolverInner {
            resolver: resolver.clone(),
            current_version: current_version.clone(),
            global: Arc::new(Mutex::new(ResolverGlobal {
                current: resolver.clone(),
                control_server: ControlServer::new(),
                current_version: current_version.clone(),
            })),
        }));
        ret.init_predefined_ns();
        ret.attach();
        ret.run_cache_cleaner(recv);
        if cfg!(not(test)) {
            ret.run_control_server();
        }
        ret
    }
    fn update_config(self, new_config: Config) -> Self {
        info!("Updating config");
        let forwarders = ForwardingResolver::create_all(&new_config);
        let zone_handlers = Self::init_zone_handlers(&new_config);
        let (send, recv) = channel::<Query>();
        let config_rc = Arc::new(new_config);
        let mut guard = self.global.lock().unwrap();
        let resolver = Arc::new(Resolver {
            cache: Cache::new(send, config_rc.clone()),
            ns_cache: NsCache::new(config_rc.clone()),
            config: config_rc.clone(),
            forwarders: forwarders,
            zone_handlers: zone_handlers,
            version: self.current_version.fetch_add(1, Ordering::SeqCst) + 1,
        });
        guard.current = resolver.clone();
        let ret = RcResolver(Arc::new(RcResolverInner {
            resolver: resolver,
            current_version: self.current_version.clone(),
            global: self.global.clone(),
        }));
        ret.init_predefined_ns();
        ret.attach();
        ret.run_cache_cleaner(recv);
        guard.control_server.set_resolver(&ret);
        ret
    }
    pub fn sync_config(self) -> Self {
        if self.version == self.current_version.load(Ordering::Relaxed) {
            return self;
        }
        info!("Migrating to latest version");
        RcResolver(Arc::new(RcResolverInner {
            resolver: self.global.lock().unwrap().current.clone(),
            current_version: self.current_version.clone(),
            global: self.global.clone(),
        }))
    }
    pub fn run_control_server(&self) {
        let mut guard = self.global.lock().unwrap();
        guard.control_server.set_resolver(self);
        guard
            .control_server
            .run()
            .expect("Failed to initialize control socket");
    }
    pub fn to_weak(&self) -> RcResolverWeak {
        RcResolverWeak(Arc::downgrade(&self.0), Arc::downgrade(&self.global))
    }
    pub fn to_keepalive(&self) -> Keepalive {
        self.global.clone().into()
    }
    pub fn current_weak() -> RcResolverWeak {
        mioco::get_userdata::<RcResolverWeak>().map_or_else(RcResolverWeak::empty, |x| (*x).clone())
    }
    pub fn current() -> Self {
        Self::current_weak()
            .upgrade()
            .expect("Called `current()` without initialization")
    }
    fn attach(&self) {
        mioco::set_userdata(self.to_weak());
        mioco::set_children_userdata(Some(self.to_weak()));
    }
}
impl Default for RcResolver {
    fn default() -> Self {
        Self::new(Config::default())
    }
}
impl RcResolverWeak {
    pub fn upgrade(&self) -> Option<RcResolver> {
        match self.0.upgrade() {
            Some(x) => Some(RcResolver(x).sync_config()),
            None => self.1.upgrade().map(|x| {
                let guard = x.lock().unwrap();
                RcResolver(Arc::new(RcResolverInner {
                    resolver: guard.current.clone(),
                    current_version: guard.current_version.clone(),
                    global: x.clone(),
                }))
            }),
        }
    }
    fn empty() -> Self {
        RcResolverWeak(Weak::new(), Weak::new())
    }
}
impl Default for RcResolverWeak {
    fn default() -> Self {
        Self::empty()
    }
}
impl RcResolver {
    fn init_zone_handlers(config: &Config) -> HashMap<Name, ZoneHandler> {
        let mut ret = config
            .forward_zones
            .iter()
            .map(|x| {
                (
                    (*x.zone).clone(),
                    ZoneHandler::Forward(x.server.clone().into_socketaddr(53)),
                )
            })
            .collect::<HashMap<_, _>>();
        config
            .local_records
            .iter()
            .filter(|x| x.record_type() == RecordType::SOA)
            .map(|x| ret.insert(x.name().clone(), ZoneHandler::Local(x.name().clone())))
            .count();
        ret
    }
    fn init_predefined_ns(&self) {
        {
            let mut guard = self.ns_cache.lock().unwrap();
            let entry = guard.lookup_or_insert(&Name::root());
            for ip in &self.config.root_servers {
                entry.add_ns(*ip, Name::root(), None);
            }
            entry.pin();
        }
        let mut resolved_entries = HashMap::<Name, Vec<Message>>::new();
        let mut pending_records = self
            .config
            .local_records
            .iter()
            .map(|x| (*x).clone())
            .collect_vec();
        let mut num_pending_records = pending_records.len();
        loop {
            pending_records = pending_records
                .into_iter()
                .filter(|rrset| {
                    let mut msg = Message::new();
                    let mut q = Query::query(rrset.name().clone(), rrset.record_type());
                    msg.set_message_type(MessageType::Response);
                    msg.set_response_code(ResponseCode::NoError);
                    #[allow(deprecated)]
                    for rec in rrset.iter() {
                        msg.add_answer(rec.clone());
                    }
                    if rrset.record_type() == RecordType::CNAME {
                        #[allow(deprecated)]
                        if let &RData::CNAME(ref target_name) = rrset.iter().next().unwrap().rdata()
                        {
                            if let Some(resolved) = resolved_entries.get(&target_name).cloned() {
                                for rrtype_msg in resolved {
                                    q.set_query_type(rrtype_msg.queries()[0].query_type());
                                    let mut new_msg = msg.clone();
                                    new_msg.add_answers(rrtype_msg.clone().take_answers());
                                    new_msg.add_query(q.clone());
                                    self.cache
                                        .update_from_message(&new_msg, RecordSource::Pinned);
                                    resolved_entries
                                        .entry(rrset.name().clone())
                                        .or_insert_with(Default::default)
                                        .push(new_msg);
                                }
                            } else {
                                return true;
                            }
                        } else {
                            debug_assert!(false, "RRset contains no or invalid record");
                            return false;
                        }
                    } else {
                        msg.add_query(q);
                        self.cache.update_from_message(&msg, RecordSource::Pinned);
                        resolved_entries
                            .entry(rrset.name().clone())
                            .or_insert_with(Default::default)
                            .push(msg);
                    }
                    false
                })
                .collect();
            if !pending_records.is_empty() || pending_records.len() == num_pending_records {
                break;
            }
            num_pending_records = pending_records.len();
        }
        for rrset in pending_records {
            warn!("Failed to resolve CNAME for local record {}", rrset.name());
        }
    }
    pub fn handle_control_command(&self, cmd: &str, params: &[String]) -> ControlResult {
        match cmd {
            "ping" => Ok("Pong".into()),
            "expire-cache" => {
                self.cache.expire_all();
                Ok("All cache entries have been marked as expired".into())
            }
            "clear-cache" => {
                self.cache.clear();
                Ok("Cleared cache".into())
            }
            "reload-config" => {
                if params.len() != 1 {
                    return Err(ControlError::Param("Invalid number of parameter".into()));
                }
                let config = Config::from_file(&params[0]).map_err(|e| {
                    ControlError::Custom(format!("Failed to load config file: {}", e))
                })?;
                info!("Reloading config from {}", params[0]);
                self.clone().update_config(config);
                Ok("Reloaded config".into())
            }
            _ => Err(ControlError::UnknownCommand),
        }
    }
    fn run_cache_cleaner(&self, ch: Receiver<Query>) {
        let version = self.version;
        let resolver_weak = self.to_weak();
        let gc_interval = *self.config.cache.gc_interval;
        mioco::spawn(move || {
            let create_timer = || -> Timer {
                let mut timer = Timer::new();
                timer.set_timeout(gc_interval.as_secs() * 1000);
                timer
            };
            let mut timer = create_timer();
            loop {
                // Avoid issues of spurious wakeup, check below
                select!(
                    r:timer => {},
                    r:ch => {},
                );
                if let Some(res) = resolver_weak.upgrade() {
                    if res.version != version {
                        info!("Resolver is reloaded, old cache update coroutine is exiting");
                        return;
                    }
                    if timer.try_read().is_some() {
                        res.cache.gc();
                        res.ns_cache.gc();
                        timer = create_timer();
                    }
                    let q = match ch.try_recv() {
                        Ok(q) => q,
                        Err(TryRecvError::Empty) => continue,
                        Err(TryRecvError::Disconnected) => break,
                    };
                    let updated = match RecursiveResolver::resolve(&q, res.clone().into()) {
                        Ok(msg) => [ResponseCode::NoError, ResponseCode::NXDomain]
                            .contains(&msg.response_code()),
                        Err(e) => {
                            info!("Failed to refresh cache for {}: {:?}", q.as_disp(), e);
                            false
                        }
                    };
                    if !updated {
                        res.cache.operate(|cache| {
                            let still_expired = cache.lookup(&q).map_or(false, |x| x.is_expired());
                            if still_expired {
                                debug!("Purging cache entry due to failed update: {}", q.as_disp());
                                cache.purge(&q);
                            }
                        });
                    }
                } else {
                    break;
                }
            }
            info!("Resolver is dropped, cache update coroutine is exiting");
        });
    }
    pub fn resolve_recursive(self, q: Query) -> Result<Message> {
        RecursiveResolver::resolve(&q, self)
    }
    fn get_zone_handler<'a>(
        &'a self,
        name: &Name,
        accept_hostname_forwarder: bool,
    ) -> Option<&'a ZoneHandler> {
        if name.is_root() {
            return None;
        }
        if accept_hostname_forwarder
            && name.num_labels() == 1
            && !self.zone_handlers.contains_key(name)
        {
            return self.zone_handlers.get(&Name::root());
        }
        match self.zone_handlers.get(name) {
            Some(x) => Some(x),
            None => self.get_zone_handler(&name.base_name(), false),
        }
    }
    fn resolve_internal(&self, q: &Query) -> Result<Message> {
        let mut futures = self
            .forwarders
            .iter()
            .cloned()
            .map(move |forwarder| {
                let qc = (*q).clone();
                let res = self.clone();
                Future::from_fn(move || forwarder.resolve(qc, res))
            })
            .collect_vec();
        let qc = (*q).clone();
        let res = self.clone();
        futures.push(Future::from_fn(move || res.resolve_recursive(qc)));
        query_multiple_handle_futures(&mut futures)
    }
    pub fn resolve_query(&self, q: Query) -> Result<Message> {
        let mut msg = Message::new();
        msg.add_query(q);
        msg.set_message_type(MessageType::Response);
        self.resolve(&mut msg)?;
        Ok(msg)
    }
    pub fn resolve(&self, msg: &mut Message) -> Result<()> {
        debug_assert_eq!(msg.queries().len(), 1);
        debug_assert!(msg.answers().is_empty());
        debug_assert!(msg.name_servers().is_empty());
        let cache_hit = self.cache.fill_response(msg);
        if cache_hit {
            return Ok(());
        }
        if let Some(handler) = self.get_zone_handler(msg.queries()[0].name(), true) {
            return handler.handle(msg, self);
        }
        let resp = (self.resolve_internal(&msg.queries()[0]))?;
        msg.copy_resp_from(&resp);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use trust_dns_proto::op::*;
    use trust_dns_proto::rr::*;

    use super::*;
    use crate::config::*;
    use crate::mioco_config_start;

    #[test]
    fn forward_zone() {
        env_logger::try_init().ok();
        mioco_config_start(|| {
            let mut config = Config::default();
            config.forward_zones.push(ForwardZoneConfig {
                zone: Name::parse("com", Some(&Name::root())).unwrap().into(),
                server: "127.0.0.254".parse().unwrap(),
            });
            let resolver = RcResolver::new(config);
            let mut q = Query::new();
            q.set_name(Name::parse("www.google.com", Some(&Name::root())).unwrap());
            q.set_query_type(RecordType::A);
            resolver.resolve_query(q.clone()).unwrap_err();
        })
        .unwrap();
    }
    #[test]
    fn forward_zone_root() {
        env_logger::try_init().ok();
        mioco_config_start(|| {
            let mut config = Config::default();
            config.forward_zones.push(ForwardZoneConfig {
                zone: Name::parse(".", Some(&Name::root())).unwrap().into(),
                server: "127.0.0.254".parse().unwrap(),
            });
            let resolver = RcResolver::new(config);
            let mut q = Query::new();
            q.set_name(Name::parse("www.google.com", Some(&Name::root())).unwrap());
            q.set_query_type(RecordType::A);
            resolver.resolve_query(q.clone()).unwrap();
            q.set_name(Name::parse("com", Some(&Name::root())).unwrap());
            q.set_query_type(RecordType::A);
            resolver.resolve_query(q.clone()).unwrap_err();
        })
        .unwrap();
    }
    #[test]
    fn local_zones() {
        env_logger::try_init().ok();
        mioco_config_start(|| {
            let config = Config::from_str(
                r#"---
cache:
    min_cache_ttl: 1
    min_response_ttl: 1
query:
    timeout: 1
local_records:
    - google.com IN 1 A 1.2.3.4
    - google.com IN 10800 SOA localhost. nobody.invalid. 1 3600 1200 604800 10800
    - x.google.com IN 1 A 5.6.7.8
    - y.google.com IN 1 AAAA ffff::0
"#,
            )
            .unwrap();
            let resolver = RcResolver::new(config);
            let mut msg = Message::new();
            msg.add_query(Query::query("google.com.".parse().unwrap(), RecordType::A));
            resolver.resolve(&mut msg).unwrap();
            assert_eq!(msg.response_code(), ResponseCode::NoError);
            assert_eq!(msg.answers().len(), 1);
            assert_eq!(msg.answers()[0].name(), msg.queries()[0].name());
            assert_eq!(
                msg.answers()[0].rdata(),
                &RData::A("1.2.3.4".parse().unwrap())
            );
            let mut msg = Message::new();
            msg.add_query(Query::query(
                "google.com.".parse().unwrap(),
                RecordType::AAAA,
            ));
            resolver.resolve(&mut msg).unwrap();
            assert_eq!(msg.response_code(), ResponseCode::NXDomain);
            assert_eq!(msg.answers().len(), 0);
            assert_eq!(msg.name_servers().len(), 1);
            let mut msg = Message::new();
            msg.add_query(Query::query(
                "www.google.com.".parse().unwrap(),
                RecordType::A,
            ));
            resolver.resolve(&mut msg).unwrap();
            assert_eq!(msg.response_code(), ResponseCode::NoError);
            assert_eq!(msg.answers().len(), 1);
            assert_eq!(msg.answers()[0].name(), msg.queries()[0].name());
            assert_eq!(
                msg.answers()[0].rdata(),
                &RData::A("1.2.3.4".parse().unwrap())
            );
            let mut msg = Message::new();
            msg.add_query(Query::query(
                "www.google.com.".parse().unwrap(),
                RecordType::AAAA,
            ));
            resolver.resolve(&mut msg).unwrap();
            assert_eq!(msg.response_code(), ResponseCode::NXDomain);
            assert_eq!(msg.answers().len(), 0);
            let mut msg = Message::new();
            msg.add_query(Query::query(
                "www.www.google.com.".parse().unwrap(),
                RecordType::A,
            ));
            resolver.resolve(&mut msg).unwrap();
            assert_eq!(msg.response_code(), ResponseCode::NoError);
            assert_eq!(msg.answers().len(), 1);
            assert_eq!(msg.answers()[0].name(), msg.queries()[0].name());
            assert_eq!(
                msg.answers()[0].rdata(),
                &RData::A("1.2.3.4".parse().unwrap())
            );
            let mut msg = Message::new();
            msg.add_query(Query::query(
                "www.www.google.com.".parse().unwrap(),
                RecordType::AAAA,
            ));
            resolver.resolve(&mut msg).unwrap();
            assert_eq!(msg.response_code(), ResponseCode::NXDomain);
            assert_eq!(msg.answers().len(), 0);
            let mut msg = Message::new();
            msg.add_query(Query::query(
                "x.google.com.".parse().unwrap(),
                RecordType::A,
            ));
            resolver.resolve(&mut msg).unwrap();
            assert_eq!(msg.response_code(), ResponseCode::NoError);
            assert_eq!(msg.answers().len(), 1);
            assert_eq!(msg.answers()[0].name(), msg.queries()[0].name());
            assert_eq!(
                msg.answers()[0].rdata(),
                &RData::A("5.6.7.8".parse().unwrap())
            );
            let mut msg = Message::new();
            msg.add_query(Query::query(
                "x.google.com.".parse().unwrap(),
                RecordType::AAAA,
            ));
            resolver.resolve(&mut msg).unwrap();
            assert_eq!(msg.response_code(), ResponseCode::NXDomain);
            assert_eq!(msg.answers().len(), 0);
            let mut msg = Message::new();
            msg.add_query(Query::query(
                "y.google.com.".parse().unwrap(),
                RecordType::AAAA,
            ));
            resolver.resolve(&mut msg).unwrap();
            assert_eq!(msg.response_code(), ResponseCode::NoError);
            assert_eq!(msg.answers().len(), 1);
            assert_eq!(msg.answers()[0].name(), msg.queries()[0].name());
            assert_eq!(
                msg.answers()[0].rdata(),
                &RData::AAAA("ffff::0".parse().unwrap())
            );
            let mut msg = Message::new();
            msg.add_query(Query::query(
                "y.google.com.".parse().unwrap(),
                RecordType::A,
            ));
            resolver.resolve(&mut msg).unwrap();
            assert_eq!(msg.response_code(), ResponseCode::NoError);
            assert_eq!(msg.answers().len(), 1);
            assert_eq!(msg.answers()[0].name(), msg.queries()[0].name());
            assert_eq!(
                msg.answers()[0].rdata(),
                &RData::A("1.2.3.4".parse().unwrap())
            );
        })
        .unwrap();
    }
    #[test]
    fn local_records() {
        env_logger::try_init().ok();
        mioco_config_start(|| {
            let config = Config::from_str(
                r#"---
cache:
    min_cache_ttl: 1
    min_response_ttl: 1
query:
    timeout: 1
local_records:
    - abc.de3cf1b9 IN 1 A 1.2.3.4
    - abc.de3cf1b9 IN 1 AAAA ffff::0
    - def.c76a6f2e IN 1 CNAME abc.de3cf1b9
    - ghi.3c8b4e39 IN 1 CNAME def.c76a6f2e
    - invalid.50979d60b0e9 IN 1 CNAME nonexist.afdf80534855
    - invalid2.a71fb2db7f92 IN 1 CNAME invalid.50979d60b0e9
forward_zones:
    - zone: afdf80534855
      server: 127.0.0.254
    - zone: 50979d60b0e9
      server: 127.0.0.254
    - zone: a71fb2db7f92
      server: 127.0.0.254
    - zone: de3cf1b9
      server: 127.0.0.254
    - zone: c76a6f2e
      server: 127.0.0.254
    - zone: 3c8b4e39
      server: 127.0.0.254
"#,
            )
            .unwrap();
            let resolver = RcResolver::new(config);
            let test = || {
                let mut msg = Message::new();
                msg.add_query(Query::query(
                    "abc.de3cf1b9.".parse().unwrap(),
                    RecordType::A,
                ));
                resolver.resolve(&mut msg).unwrap();
                assert_eq!(msg.response_code(), ResponseCode::NoError);
                assert_eq!(msg.answers().len(), 1);
                assert_eq!(
                    msg.answers()[0].rdata(),
                    &RData::A("1.2.3.4".parse().unwrap())
                );
                let mut msg = Message::new();
                msg.add_query(Query::query(
                    "def.c76a6f2e.".parse().unwrap(),
                    RecordType::A,
                ));
                resolver.resolve(&mut msg).unwrap();
                assert_eq!(msg.response_code(), ResponseCode::NoError);
                assert_eq!(msg.answers().len(), 2);
                assert_eq!(
                    msg.answers()[1].rdata(),
                    &RData::A("1.2.3.4".parse().unwrap())
                );
                let mut msg = Message::new();
                msg.add_query(Query::query(
                    "ghi.3c8b4e39.".parse().unwrap(),
                    RecordType::A,
                ));
                resolver.resolve(&mut msg).unwrap();
                assert_eq!(msg.response_code(), ResponseCode::NoError);
                assert_eq!(msg.answers().len(), 3);
                assert_eq!(
                    msg.answers()[2].rdata(),
                    &RData::A("1.2.3.4".parse().unwrap())
                );
                let mut msg = Message::new();
                msg.add_query(Query::query(
                    "ghi.3c8b4e39.".parse().unwrap(),
                    RecordType::AAAA,
                ));
                resolver.resolve(&mut msg).unwrap();
                assert_eq!(msg.response_code(), ResponseCode::NoError);
                assert_eq!(msg.answers().len(), 3);
                assert_eq!(
                    msg.answers()[2].rdata(),
                    &RData::AAAA("ffff::0".parse().unwrap())
                );
                let mut msg = Message::new();
                msg.add_query(Query::query(
                    "invalid.50979d60b0e9.".parse().unwrap(),
                    RecordType::A,
                ));
                resolver.resolve(&mut msg).unwrap_err();
                let mut msg = Message::new();
                msg.add_query(Query::query(
                    "invalid2.a71fb2db7f92.".parse().unwrap(),
                    RecordType::A,
                ));
                resolver.resolve(&mut msg).unwrap_err();
            };
            test();
            test();
            resolver.cache.expire_all();
            test();
            test();
        })
        .unwrap();
    }
    #[test]
    fn simple_recursive_query() {
        env_logger::try_init().ok();
        mioco_config_start(|| {
            let config = Config::default();
            let resolver = RcResolver::new(config);
            let mut q = Query::new();
            q.set_name(Name::parse("www.google.com", Some(&Name::root())).unwrap());
            let result = resolver.resolve_recursive(q).unwrap();
            assert!(result.answers().len() > 0);
        })
        .unwrap();
    }
    #[test]
    fn reload_config() {
        env_logger::try_init().ok();
        mioco_config_start(|| {
            use mioco::yield_now;
            let config = Config::default();
            let mut q = Query::new();
            q.set_name(Name::parse("www.google.com", Some(&Name::root())).unwrap());
            let (resolver_weak, resolver) = {
                let resolver = RcResolver::new(config);
                let new_resolver = resolver.clone().update_config(Config::default());
                assert!(!Arc::ptr_eq(&resolver, &new_resolver));
                assert!(Arc::ptr_eq(
                    &resolver.clone().sync_config().resolver,
                    &new_resolver.resolver
                ));
                let result = new_resolver.clone().resolve_recursive(q.clone()).unwrap();
                assert!(result.answers().len() > 0);
                let resolver_weak = resolver.to_weak();
                let resolver = new_resolver.clone();
                #[allow(unused_must_use)]
                {
                    resolver.clone();
                }
                (resolver_weak, new_resolver)
            };
            yield_now();
            assert!(resolver_weak.0.upgrade().is_none());
            let result = resolver.clone().resolve_recursive(q.clone()).unwrap();
            assert!(result.answers().len() > 0);
            assert!(Arc::ptr_eq(&resolver, &resolver.clone().sync_config()));
            let result = resolver.clone().resolve_recursive(q.clone()).unwrap();
            assert!(result.answers().len() > 0);
            let resolver = resolver.clone().update_config(Config::default());
            assert!(resolver_weak.0.upgrade().is_none());
            let result = resolver.clone().resolve_recursive(q.clone()).unwrap();
            assert!(result.answers().len() > 0);
            assert!(Arc::ptr_eq(&resolver, &resolver.clone().sync_config()));
            let result = resolver.clone().resolve_recursive(q.clone()).unwrap();
            assert!(result.answers().len() > 0);
        })
        .unwrap();
    }
    #[test]
    #[allow(unused_variables)]
    fn current() {
        env_logger::try_init().ok();
        mioco_config_start(|| {
            let config = Config::default();
            let resolver = RcResolver::new(config);
            RcResolver::current();
            mioco::spawn(move || {
                RcResolver::current();
                mioco::spawn(move || {
                    RcResolver::current();
                })
                .join()
                .unwrap();
            })
            .join()
            .unwrap();
        })
        .unwrap();
    }
}
