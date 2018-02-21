use std::sync::{Arc, Weak};
use std::sync::atomic::{AtomicUsize, Ordering, ATOMIC_USIZE_INIT};
use std::default::Default;
use std::sync::mpsc::TryRecvError;
use std::ops::Deref;
use std::collections::HashSet;

use mioco;
use mioco::timer::Timer;
use mioco::sync::Mutex;
use mioco::sync::mpsc::{channel, Receiver};
use trust_dns::op::{Message, ResponseCode, Query};
use trust_dns::rr::{Name};
use itertools::Itertools;

use utils::{Result, MessageExt, AsDisplay, Future};
use cache::Cache;
use nscache::NsCache;
use config::Config;
use recursive::RecursiveResolver;
use forwarding::ForwardingResolver;
use query::query_multiple_handle_futures;
use control::{ControlServer, Error as ControlError, ControlResult};

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
pub struct Resolver {
    pub cache: Cache,
    pub ns_cache: NsCache,
    pub config: Arc<Config>,
    forwarders: Vec<Arc<ForwardingResolver>>,
    forward_zones: HashSet<Name>,
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
#[derive(Clone)]
pub struct RcResolverWeak(Weak<RcResolverInner>, Weak<Mutex<ResolverGlobal>>);

impl RcResolver {
    pub fn new(config: Config) -> Self {
        let forwarders = ForwardingResolver::create_all(&config);
        let forward_zones = config.forward_zones.iter().map(|x| (*x.zone).clone()).collect();
        let (send, recv) = channel::<Query>();
        let config_rc = Arc::new(config);
        let resolver = Arc::new(Resolver {
            cache: Cache::new(send, config_rc.clone()),
            ns_cache: NsCache::new(config_rc.clone()),
            config: config_rc.clone(),
            forwarders: forwarders,
            forward_zones: forward_zones,
            version: 0,
        });
        let current_version = Arc::new(ATOMIC_USIZE_INIT);
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
        let forward_zones = new_config.forward_zones.iter().map(|x| (*x.zone).clone()).collect();
        let (send, recv) = channel::<Query>();
        let config_rc = Arc::new(new_config);
        let mut guard = self.global.lock().unwrap();
        let resolver = Arc::new(Resolver {
            cache: Cache::new(send, config_rc.clone()),
            ns_cache: NsCache::new(config_rc.clone()),
            config: config_rc.clone(),
            forwarders: forwarders,
            forward_zones: forward_zones,
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
        guard.control_server.run().expect("Failed to initialize control socket");
    }
    pub fn to_weak(&self) -> RcResolverWeak {
        RcResolverWeak(Arc::downgrade(&self.0), Arc::downgrade(&self.global))
    }
    pub fn current_weak() -> RcResolverWeak {
        mioco::get_userdata::<RcResolverWeak>()
        .map_or_else(RcResolverWeak::empty, |x| (*x).clone())
    }
    pub fn current() -> Self {
        Self::current_weak().upgrade().expect("Called `current()` without initialization")
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
            })
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
    fn init_predefined_ns(&self) {
        let mut guard = self.ns_cache.lock().unwrap();
        {
            let entry = guard.lookup_or_insert(&Name::root());
            for ip in &self.config.root_servers {
                entry.add_ns(*ip, Name::root(), None);
            }
            entry.pin();
        }
        for forward_zone in &self.config.forward_zones {
            let entry = guard.lookup_or_insert(&*forward_zone.zone);
            entry.add_ns(forward_zone.server, forward_zone.zone.clone(), None);
            entry.pin();
        }
    }
    pub fn handle_control_command(&self, cmd: &str, params: &[String]) -> ControlResult {
        match cmd {
            "ping" => Ok("Pong".into()),
            "expire-cache" => {
                self.cache.expire_all();
                Ok("All cache entries have been marked as expired".into())
            },
            "clear-cache" => {
                self.cache.clear();
                Ok("Cleared cache".into())
            },
            "reload-config" => {
                if params.len() != 1 {
                    return Err(ControlError::Param("Invalid number of parameter".into()));
                }
                let config = Config::from_file(&params[0]).map_err(|e| ControlError::Custom(format!("Failed to load config file: {}", e)))?;
                info!("Reloading config from {}", params[0]);
                self.clone().update_config(config);
                Ok("Reloaded config".into())
            }
            _ => Err(ControlError::UnknownCommand),
        }
    }
    #[allow(while_let_loop)]
    fn run_cache_cleaner(&self, ch: Receiver<Query>) {
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
                    if timer.try_read().is_some() {
                        res.cache.gc();
                        res.ns_cache.gc();
                        timer = create_timer();
                        continue;
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
                        },
                    };
                    if !updated {
                        res.cache.operate(|cache| {
                            let still_expired = cache.lookup(&q)
                            .map_or(false, |x| x.is_expired());
                            if still_expired {
                                debug!("Purging cache entry due to failed update: {}",
                                       q.as_disp());
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
    fn is_forward_zone(&self, name: &Name) -> bool {
        if name.is_root() {
            return false;
        }
        if self.forward_zones.contains(name) {
            return true;
        }
        self.is_forward_zone(&name.base_name())
    }
    fn resolve_internal(&self, q: &Query) -> Result<Message> {
        if self.is_forward_zone(q.name()) {
            // Server is registered in nscache
            return self.clone().resolve_recursive((*q).clone());
        }
        let mut futures = self.forwarders.iter().cloned().map(move |forwarder| {
            let qc = (*q).clone();
            let res = self.clone();
            Future::from_fn(move || forwarder.resolve(qc, res))
        }).collect_vec();
        let qc = (*q).clone();
        let res = self.clone();
        futures.push(Future::from_fn(move || res.resolve_recursive(qc)));
        query_multiple_handle_futures(&mut futures)
    }
    pub fn resolve(&self, msg: &mut Message) -> Result<()> {
        debug_assert_eq!(msg.queries().len(), 1);
        debug_assert!(msg.answers().is_empty());
        debug_assert!(msg.name_servers().is_empty());
        let cache_hit = self.cache.fill_response(msg);
        if cache_hit {
            return Ok(());
        }
        let resp = try!(self.resolve_internal(&msg.queries()[0]));
        msg.copy_resp_from(&resp);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use env_logger;
    use trust_dns::op::*;
    use trust_dns::rr::*;
    use mioco;

    use super::*;
    use ::mioco_config_start;
    use ::config::*;

    #[test]
    fn forward_zone() {
        env_logger::try_init().is_ok();
        mioco_config_start(|| {
            let mut config = Config::default();
            config.forward_zones.push(ForwardZoneConfig {
                zone: Name::parse("com", Some(&Name::root())).unwrap().into(),
                server: "127.0.0.254".parse().unwrap(),
            });
            let resolver = RcResolver::new(config);
            let mut q = Query::new();
            q.set_name(Name::parse("www.google.com", Some(&Name::root())).unwrap());
            resolver.resolve_internal(&q).unwrap_err();
        }).unwrap();
    }
    #[test]
    fn simple_recursive_query() {
        env_logger::try_init().is_ok();
        mioco_config_start(|| {
            let config = Config::default();
            let resolver = RcResolver::new(config);
            let mut q = Query::new();
            q.set_name(Name::parse("www.google.com", Some(&Name::root())).unwrap());
            let result = resolver.resolve_recursive(q).unwrap();
            assert!(result.answers().len() > 0);
        }).unwrap();
    }
    #[test]
    fn reload_config() {
        env_logger::try_init().is_ok();
        mioco_config_start(|| {
            use mioco::yield_now;
            let config = Config::default();
            let mut q = Query::new();
            q.set_name(Name::parse("www.google.com", Some(&Name::root())).unwrap());
            let (resolver_weak, resolver) = {
                let resolver = RcResolver::new(config);
                let new_resolver = resolver.clone().update_config(Config::default());
                assert!(!Arc::ptr_eq(&resolver, &new_resolver));
                assert!(Arc::ptr_eq(&resolver.clone().sync_config().resolver, &new_resolver.resolver));
                let result = new_resolver.clone().resolve_recursive(q.clone()).unwrap();
                assert!(result.answers().len() > 0);
                let resolver_weak = resolver.to_weak();
                let resolver = new_resolver.clone();
                resolver.clone();
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
        }).unwrap();
    }
    #[test]
    #[allow(unused_variables)]
    fn current() {
        env_logger::try_init().is_ok();
        mioco_config_start(|| {
            let config = Config::default();
            let resolver = RcResolver::new(config);
            RcResolver::current();
            mioco::spawn(move || {
                RcResolver::current();
                mioco::spawn(move || {
                    RcResolver::current();
                }).join().unwrap();
            }).join().unwrap();
        }).unwrap();
    }
}
