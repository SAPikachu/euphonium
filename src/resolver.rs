use std::sync::{Arc, Weak};
use std::default::Default;
use std::sync::mpsc::TryRecvError;

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
    control_server: Mutex<ControlServer>,
}
macro_attr! {
    #[derive(Clone, NewtypeFrom!, NewtypeDeref!)]
    pub struct RcResolver(Arc<Resolver>);
}
macro_attr! {
    #[derive(Clone, NewtypeFrom!)]
    pub struct RcResolverWeak(Weak<Resolver>);
}

impl RcResolver {
    pub fn new(config: Config) -> Self {
        let forwarders = ForwardingResolver::create_all(&config);
        let (send, recv) = channel::<Query>();
        let config_rc = Arc::new(config);
        let ret: RcResolver = Arc::new(Resolver {
            cache: Cache::new(send, config_rc.clone()),
            ns_cache: NsCache::new(config_rc.clone()),
            config: config_rc.clone(),
            forwarders: forwarders,
            control_server: Mutex::new(ControlServer::new()),
        }).into();
        if cfg!(not(test)) {
            ret.control_server.lock().unwrap().run(&ret)
            .expect("Failed to initialize control socket");
        }
        ret.init_root_servers();
        ret.attach();
        ret.run_cache_cleaner(recv);
        ret
    }
    #[cfg(test)]
    pub fn run_control_server(&self) {
        self.control_server.lock().unwrap().run(self)
        .expect("Failed to initialize control socket");
    }
    pub fn to_weak(&self) -> RcResolverWeak {
        RcResolverWeak(Arc::downgrade(self))
    }
    pub fn current_weak() -> RcResolverWeak {
        mioco::get_userdata::<RcResolverWeak>()
        .map_or_else(RcResolverWeak::empty, |x| (*x).clone())
    }
    pub fn current() -> Self {
        Self::current_weak().upgrade().expect("Called `current()` without initialization")
    }
    fn attach(&self) {
        assert!(RcResolver::current_weak().upgrade().is_none());
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
        self.0.upgrade().map(|x| x.into())
    }
    fn empty() -> Self {
        RcResolverWeak(Weak::new())
    }
}
impl RcResolver {
    fn init_root_servers(&self) {
        let mut guard = self.ns_cache.lock().unwrap();
        let mut entry = guard.lookup_or_insert(&Name::root());
        entry.pin();
        for ip in &self.config.root_servers {
            entry.add_ns(*ip, Name::root(), None);
        }
    }
    pub fn handle_control_command(&self, cmd: &str, _: &[String]) -> ControlResult {
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
                                   .contains(&msg.get_response_code()),
                        Err(_) => false,
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
            debug!("Resolver is dropped, cache update coroutine is exiting");
        });
    }
    fn resolve_recursive(self, q: Query) -> Result<Message> {
        RecursiveResolver::resolve(&q, self)
    }
    fn resolve_internal(&self, q: &Query) -> Result<Message> {
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
        debug_assert!(msg.get_queries().len() == 1);
        debug_assert!(msg.get_answers().is_empty());
        debug_assert!(msg.get_name_servers().is_empty());
        let cache_hit = self.cache.fill_response(msg);
        if cache_hit {
            return Ok(());
        }
        let resp = try!(self.resolve_internal(&msg.get_queries()[0]));
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
    fn simple_recursive_query() {
        env_logger::init().is_ok();
        mioco_config_start(|| {
            let config = Config::default();
            let resolver = RcResolver::new(config);
            let mut q = Query::new();
            q.name(Name::parse("www.google.com", Some(&Name::root())).unwrap());
            let result = resolver.resolve_recursive(q).unwrap();
            assert!(result.get_answers().len() > 0);
        }).unwrap();
    }
    #[test]
    #[allow(unused_variables)]
    fn current() {
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
    #[test]
    #[should_panic]
    #[allow(unused_variables)]
    fn no_multiple_instances() {
        // FIXME: We have to use mioco::start here, using `mioco_config_start` (which
        // doesn't handle panics in coroutines) will crash the test process
        mioco::start(|| {
            let config = Config::default();
            let resolver = RcResolver::new(config);
            let config = Config::default();
            let resolver2 = RcResolver::new(config);
        }).unwrap();
    }
}
