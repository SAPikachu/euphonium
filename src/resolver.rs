use std::sync::{Arc, Weak};
use std::default::Default;

use mioco;
use mioco::sync::mpsc::{channel, Receiver};
use trust_dns::op::{Message, ResponseCode, Query};
use trust_dns::rr::{Name};

use utils::{Result, MessageExt, AsDisplay};
use cache::Cache;
use nscache::NsCache;
use config::Config;
use recursive::RecursiveResolver;

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
    pub cache: Cache,
    pub ns_cache: NsCache,
    pub config: Config,
}
custom_derive! {
    #[derive(Clone, NewtypeFrom, NewtypeDeref)]
    pub struct RcResolver(Arc<Resolver>);
}
custom_derive! {
    #[derive(Clone, NewtypeFrom)]
    pub struct RcResolverWeak(Weak<Resolver>);
}

impl RcResolver {
    pub fn new(config: Config) -> Self {
        let (send, recv) = channel::<Query>();
        let ret: RcResolver = Arc::new(Resolver {
            cache: Cache::with_expiration_notifier(send),
            ns_cache: NsCache::default(),
            config: config,
        }).into();
        ret.init_root_servers();
        ret.attach();
        ret.handle_cache_expiration_channel(recv);
        ret
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
    fn handle_cache_expiration_channel(&self, ch: Receiver<Query>) {
        let resolver_weak = self.to_weak();
        mioco::spawn(move || {
            while let Ok(q) = ch.recv() {
                if let Some(res) = resolver_weak.upgrade() {
                    let updated = match RecursiveResolver::resolve(
                        &q, res.clone().into(), true
                    ) {
                        Ok(msg) => [ResponseCode::NoError, ResponseCode::NXDomain]
                                   .contains(&msg.get_response_code()),
                        Err(_) => false,
                    };
                    if !updated {
                        res.cache.operate(q.get_name(), |entry, _| {
                            let still_expired = entry.lookup_entry(q.get_query_type())
                            .map_or(false, |x| x.is_expired());
                            if still_expired {
                                debug!("Purging cache entry due to failed update: {}",
                                       q.as_disp());
                                entry.purge(q.get_query_type());
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
    fn resolve_recursive(&self, q: &Query) -> Result<Message> {
        RecursiveResolver::resolve(q, self.clone(), false)
    }
    pub fn resolve(&self, msg: &mut Message) -> Result<()> {
        debug_assert!(msg.get_queries().len() == 1);
        debug_assert!(msg.get_answers().is_empty());
        debug_assert!(msg.get_name_servers().is_empty());
        let query_type = msg.get_queries()[0].get_query_type();
        let name = msg.get_queries()[0].get_name().clone();
        let cache_hit = self.cache.lookup_with_type(
            &name,
            query_type,
            |cached| msg.copy_resp_from(&cached),
        ).is_some();
        if cache_hit {
            return Ok(());
        }
        let resp = try!(self.resolve_recursive(&msg.get_queries()[0]));
        msg.copy_resp_from(&resp);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use trust_dns::op::*;
    use trust_dns::rr::*;
    use mioco;

    use super::*;
    use ::mioco_config_start;
    use ::config::*;

    #[test]
    fn simple_recursive_query() {
        mioco_config_start(|| {
            let config = Config::default();
            let resolver = RcResolver::new(config);
            let mut q = Query::new();
            q.name(Name::parse("www.google.com", Some(&Name::root())).unwrap());
            let result = resolver.resolve_recursive(&q).unwrap();
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
