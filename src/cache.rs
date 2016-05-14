use std::time::{SystemTime, Duration};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::cmp::{min, max};

use mioco::sync::{Mutex};
use mioco::sync::mpsc::{Sender};
use trust_dns::rr::{Name, RecordType, Record};
use trust_dns::op::{Message, OpCode, MessageType, ResponseCode, Query};

use utils::{CloneExt, MessageExt, AsDisplay};
use resolver::{RcResolver, RcResolverWeak};

pub type Key = Name;

#[allow(dead_code)] // FIXME
#[derive(Debug, Copy, Clone)]
pub enum TtlMode {
    Original,
    Fixed(u32),
    Relative(SystemTime),
}
pub struct RecordTypeEntry {
    message: Message,
    expiration: Option<SystemTime>,
    ttl: TtlMode,
    expiration_notifier: Option<Sender<Query>>,
    expiration_notified: AtomicBool,
    resolver: RcResolverWeak,
}
impl RecordTypeEntry {
    pub fn maybe_notify_expiration(&self) {
        let sender = match self.expiration_notifier {
            None => return,
            Some(ref s) => s,
        };
        if !self.is_expired() {
            return;
        }
        // TODO: Maybe we need to notify later to handle SERVFAIL?
        if self.expiration_notified.load(Ordering::Relaxed) {
            // Already notified
            return;
        }
        if self.expiration_notified.swap(true, Ordering::Relaxed) {
            // Lost race
            return;
        }
        let q = self.message.get_queries()[0].clone();
        debug!("Entry expired: {}", q.as_disp());
        sender.send(q.into()).is_ok();
    }
    pub fn is_expired(&self) -> bool {
        match self.expiration {
            None => false,
            Some(ref t) => t <= &SystemTime::now(),
        }
    }
    pub fn adjust_ttl(&self, rec: &mut Record) {
        match self.ttl {
            TtlMode::Original => {},
            TtlMode::Fixed(secs) => { rec.ttl(secs); },
            TtlMode::Relative(relto) => {
                match relto.elapsed() {
                    Err(e) => {
                        warn!("Failed to get elapsed time for setting TTL: {:?}", e);
                    },
                    Ok(dur) => {
                        let diff = min(dur.as_secs(), i32::max_value() as u64) as u32;
                        let mut new_ttl = rec.get_ttl().saturating_sub(diff);
                        if let Some(res) = self.resolver.upgrade() {
                            new_ttl = max(new_ttl, res.config.cache.min_response_ttl);
                        }
                        rec.ttl(new_ttl);
                    },
                };
            },
        };
    }
}
#[derive(Default)]
pub struct Entry {
    records: HashMap<RecordType, RecordTypeEntry>,
}
impl Entry {
    pub fn lookup_entry(&self, t: RecordType) -> Option<&RecordTypeEntry> {
        self.records.get(&t)
    }
    pub fn purge(&mut self, t: RecordType) -> Option<Message> {
        self.records.remove(&t).map(|entry| entry.message)
    }
    pub fn lookup_adjusted(&self, t: RecordType) -> Option<Message> {
        self.records.get(&t).map(|entry| {
            entry.maybe_notify_expiration();
            let mut ret = Message::new();
            ret.copy_resp_with(&entry.message, |rec| {
                let mut new_rec = rec.clone();
                entry.adjust_ttl(&mut new_rec);
                new_rec
            });
            ret
        })
    }
    pub fn update(&mut self, msg: &Message, expiration_notifier: Option<Sender<Query>>) {
        // TODO: Validate message before updating
        // TODO: Confirm that the new message is more preferable than existing one
        assert!(msg.get_queries().len() == 1);
        let t = msg.get_queries()[0].get_query_type();
        let accepted_responses = [ResponseCode::NoError, ResponseCode::NXDomain];
        if !accepted_responses.contains(&msg.get_response_code()) {
            return;
        }
        let all_records = msg.get_answers().iter()
        .chain(msg.get_name_servers())
        .chain(msg.get_additional())
        .filter(|x| x.get_rr_type() != RecordType::OPT);
        // TODO: NXDomain should be cached for shorter time
        let resolver = RcResolver::current();
        let min_cache_ttl = resolver.config.cache.min_cache_ttl;
        let cache_ttl = max(
            min_cache_ttl,
            all_records.map(|x| x.get_ttl()).min().unwrap_or(min_cache_ttl),
        ) as u64;
        debug!("Updating cache: {} -> {} (TTL: {})",
               msg.get_queries()[0].as_disp(), msg.as_disp(), cache_ttl);
        let mut cache_msg = msg.clone_resp();
        cache_msg.add_query(msg.get_queries()[0].clone());
        self.records.insert(t, RecordTypeEntry {
            message: cache_msg,
            expiration: Some(SystemTime::now() + Duration::from_secs(cache_ttl)),
            ttl: TtlMode::Relative(SystemTime::now()),
            expiration_notifier: expiration_notifier,
            expiration_notified: AtomicBool::new(false),
            resolver: resolver.to_weak(),
        });
    }
}
#[derive(Default)]
pub struct CachePlain {
    entries: HashMap<Key, Entry>,
    expiration_notifier: Option<Sender<Query>>,
}
pub type CacheInst = Mutex<CachePlain>; 

impl CachePlain {
    pub fn lookup(&self, key: &Key) -> Option<&Entry> {
        self.entries.get(key)
    }
    pub fn lookup_or_insert(&mut self, key: &Key) -> &mut Entry {
        self.entries.entry(key.clone()).or_insert_with(Entry::default)
    }
}
pub struct Cache {
    inst: CacheInst,
}
pub type RcCache = Arc<Cache>;
impl Cache {
    pub fn with_expiration_notifier(notifier: Sender<Query>) -> Self {
        Cache {
            inst: Mutex::new(CachePlain {
                entries: HashMap::new(),
                expiration_notifier: Some(notifier),
            }),
        }
    }
    pub fn lookup_with_type<F, R>(&self, key: &Key, t: RecordType, op: F) -> Option<R>
        where F: FnOnce(Message) -> R,
    {
        let guard = self.inst.lock().expect("The mutex shouldn't be poisoned");
        guard.lookup(key).and_then(|entry| entry.lookup_adjusted(t)).map(op)
    }
    pub fn operate<F, R>(&self, key: &Key, op: F) -> R
        where F: FnOnce(&mut Entry, Option<Sender<Query>>) -> R,
    {
        let mut guard = self.inst.lock().expect("The mutex shouldn't be poisoned");
        let notifier = guard.expiration_notifier.clone();
        op(guard.lookup_or_insert(key), notifier)
    }
    pub fn update_from_message(&self, msg: &Message) {
        if cfg!(debug_assertions) {
            assert!(msg.get_op_code() == OpCode::Query);
            assert!(msg.get_message_type() == MessageType::Response);
            assert!(msg.get_queries().len() == 1);
            if msg.get_answers().is_empty() {
                assert!(msg.get_response_code() != ResponseCode::NoError);
            } else {
                let name = msg.get_queries()[0].get_name();
                assert!(msg.get_answers().iter().any(|x| x.get_name() == name));
            }
        }
        let name = msg.get_queries()[0].get_name();
        self.operate(name, |entry, notifier| entry.update(&msg, notifier));
    }
}
impl Default for Cache {
    fn default() -> Self {
        Cache {
            inst: Mutex::new(CachePlain {
                entries: HashMap::new(),
                expiration_notifier: None,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::*;
    use std::time::{SystemTime, Duration};
    use trust_dns::rr::*;
    use trust_dns::op::*;
    use super::*;
    use resolver::*;
    use ::mioco_config_start;

    fn name(raw: &str) -> Name {
        Name::parse(raw, Some(&Name::root())).unwrap()
    }
    #[test]
    fn test_cache_case_insensitivity() {
        let mut cache = CachePlain::default();
        cache.lookup_or_insert(&name("www.google.com"));
        assert!(cache.lookup(&name("www.google.com")).is_some());
        assert!(cache.lookup(&name("www.baidu.com")).is_none());
        assert!(cache.lookup(&name("wWw.goOgle.coM")).is_some());
    }
    #[test]
    fn test_ttl_adjust() {
        mioco_config_start(move || {
            let resolver = RcResolver::default();
            let min_ttl = resolver.config.cache.min_response_ttl;
            let mut entry = RecordTypeEntry {
                message: Message::new(),
                expiration: None,
                ttl: TtlMode::Original,
                expiration_notifier: None,
                expiration_notified: AtomicBool::new(false),
                resolver: resolver.to_weak(),
            };
            let mut rec = Record::new();
            macro_rules! adjust {
                ($e:expr) => {{
                    entry.ttl = $e;
                    entry.adjust_ttl(&mut rec);
                }};
            };
            rec.ttl(120);
            adjust!(TtlMode::Original);
            assert_eq!(rec.get_ttl(), 120);
            adjust!(TtlMode::Fixed(240));
            assert_eq!(rec.get_ttl(), 240);

            adjust!(TtlMode::Relative(SystemTime::now()));
            assert_eq!(rec.get_ttl(), 240);
            adjust!(TtlMode::Relative(SystemTime::now() - Duration::from_secs(10)));
            assert_eq!(rec.get_ttl(), 230);
            adjust!(TtlMode::Relative(SystemTime::now() - Duration::new(10, 999999999)));
            assert_eq!(rec.get_ttl(), 219);
            adjust!(TtlMode::Relative(SystemTime::now() - Duration::from_secs(500)));
            assert_eq!(rec.get_ttl(), min_ttl);

            rec.ttl(240);
            adjust!(TtlMode::Relative(SystemTime::now() - Duration::from_secs(u32::max_value() as u64)));
            assert_eq!(rec.get_ttl(), min_ttl);
            rec.ttl(240);

            // Using `Duration::from_secs(u64::max_value())` will silently overflow and give us
            // incorrect result, so we test with `u64::max_value() >> 1` here.
            // Ref: https://github.com/rust-lang/rust/issues/32070
            adjust!(TtlMode::Relative(SystemTime::now() - Duration::from_secs(u64::max_value() >> 1)));
            assert_eq!(rec.get_ttl(), min_ttl);
        }).unwrap();
    }
}
