use std::time::{SystemTime, Duration};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::cmp::{min, max};

use mioco::sync::{Mutex};
use mioco::sync::mpsc::{Sender};
use trust_dns::rr::{Name, RecordType, Record};
use trust_dns::op::{Message, OpCode, MessageType, ResponseCode, Query};

use utils::{CloneExt, MessageExt, AsDisplay};
use resolver::{RcResolver, RcResolverWeak};

pub type Key = Name;

#[derive(Debug, Copy, Clone)]
pub enum TtlMode {
    Original,
    Fixed(u32),
    Relative(SystemTime),
}
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum RecordSource {
    Forwarder,
    Recursive,
    Pinned,
}
pub struct RecordTypeEntry {
    message: Message,
    expiration: Option<SystemTime>,
    ttl: TtlMode,
    expiration_notifier: Option<Sender<Query>>,
    expiration_notified: AtomicBool,
    resolver: RcResolverWeak,
    source: RecordSource,
    global_expiration_counter: Arc<AtomicUsize>,
    record_expiration_counter: usize,
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
            Some(ref t) => {
                if self.record_expiration_counter !=
                    self.global_expiration_counter.load(Ordering::Relaxed)
                {
                    true
                } else {
                    t <= &SystemTime::now()
                }
            },
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
                        if self.is_expired() {
                            new_ttl = 1
                        }
                        rec.ttl(new_ttl);
                    },
                };
            },
        };
    }
}
pub struct Entry {
    records: HashMap<RecordType, RecordTypeEntry>,
    expiration_notifier: Option<Sender<Query>>,
    global_expiration_counter: Arc<AtomicUsize>,
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
    fn get_ttl_mode(&self, source: RecordSource) -> TtlMode {
        match source {
            RecordSource::Pinned => TtlMode::Original,
            RecordSource::Forwarder => TtlMode::Fixed(1),
            RecordSource::Recursive => TtlMode::Relative(SystemTime::now()),
        }
    }
    pub fn update(&mut self, msg: &Message, source: RecordSource) {
        // TODO: Validate message before updating
        // TODO: Confirm that the new message is more preferable than existing one
        assert!(msg.get_queries().len() == 1);
        let t = msg.get_queries()[0].get_query_type();
        let accepted_responses = [ResponseCode::NoError, ResponseCode::NXDomain];
        if !accepted_responses.contains(&msg.get_response_code()) {
            return;
        }
        if let Some(existing) = self.records.get(&t) {
            if !existing.is_expired() && existing.source >= source {
                // Existing record is more preferable
                return;
            }
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
        let ttl_mode = self.get_ttl_mode(source);
        self.records.insert(t, RecordTypeEntry {
            message: cache_msg,
            expiration: Some(SystemTime::now() + Duration::from_secs(cache_ttl)),
            ttl: ttl_mode,
            expiration_notifier: self.expiration_notifier.clone(),
            expiration_notified: AtomicBool::new(false),
            resolver: resolver.to_weak(),
            source: source,
            global_expiration_counter: self.global_expiration_counter.clone(),
            record_expiration_counter: self.global_expiration_counter.load(Ordering::Relaxed),
        });
    }
}

#[derive(Default)]
pub struct CachePlain {
    entries: HashMap<Key, Entry>,
    expiration_notifier: Option<Sender<Query>>,
    global_expiration_counter: Arc<AtomicUsize>,
}
pub type CacheInst = Mutex<CachePlain>; 

impl CachePlain {
    pub fn lookup(&self, key: &Key) -> Option<&Entry> {
        self.entries.get(key)
    }
    fn lookup_mut_internal(&mut self, key: &Key) -> &mut Entry {
        self.entries.get_mut(key).unwrap()
    }
    fn create_entry(&mut self, key: &Key) -> &mut Entry {
        let notifier = self.expiration_notifier.clone();
        let global_expiration_counter = self.global_expiration_counter.clone();
        self.entries.entry(key.clone()).or_insert_with(move || Entry {
            records: HashMap::default(),
            expiration_notifier: notifier,
            global_expiration_counter: global_expiration_counter,
        })
    }
    pub fn lookup_or_insert(&mut self, key: &Key) -> &mut Entry {
        // We can't inline these functions due to errors from borrow checker
        if self.entries.contains_key(key) {
            self.lookup_mut_internal(key)
        } else {
            self.create_entry(key)
        }
    }
}
pub struct Cache {
    inst: CacheInst,
    global_expiration_counter: Arc<AtomicUsize>,
}
pub type RcCache = Arc<Cache>;
impl Cache {
    pub fn with_expiration_notifier(notifier: Sender<Query>) -> Self {
        let counter = Arc::new(AtomicUsize::default());
        Cache {
            global_expiration_counter: counter.clone(),
            inst: Mutex::new(CachePlain {
                entries: HashMap::new(),
                expiration_notifier: Some(notifier),
                global_expiration_counter: counter.clone(),
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
        where F: FnOnce(&mut Entry) -> R,
    {
        let mut guard = self.inst.lock().expect("The mutex shouldn't be poisoned");
        op(guard.lookup_or_insert(key))
    }
    pub fn update_from_message(&self, msg: &Message, source: RecordSource) {
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
        self.operate(name, |entry| entry.update(msg, source));
    }
    pub fn expire_all(&self) {
        self.global_expiration_counter.fetch_add(1, Ordering::Relaxed);
    }
    pub fn clear(&self) {
        let mut guard = self.inst.lock().expect("The mutex shouldn't be poisoned");
        guard.entries.clear();
    }
}
impl Default for Cache {
    fn default() -> Self {
        let counter = Arc::new(AtomicUsize::default());
        Cache {
            global_expiration_counter: counter.clone(),
            inst: Mutex::new(CachePlain {
                entries: HashMap::new(),
                expiration_notifier: None,
                global_expiration_counter: counter.clone(),
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
    use utils::*;
    use ::mioco_config_start;

    fn name(raw: &str) -> Name {
        Name::parse(raw, Some(&Name::root())).unwrap()
    }
    #[test]
    fn test_record_preference() {
        mioco_config_start(move || {
            let resolver = RcResolver::default();
            let mut msg1 = Message::new();
            msg1.message_type(MessageType::Response);
            msg1.op_code(OpCode::Query);
            let name = Name::parse("www.google.com", Some(&Name::root())).unwrap();
            let t = RecordType::A;
            let mut q = Query::new();
            q.name(name.clone());
            q.query_type(t);
            msg1.add_query(q.clone());
            let mut msg2 = msg1.clone_resp_for(&q);
            let mut rec = Record::new();
            rec.ttl(3600);
            rec.name(name.clone());
            msg1.add_answer(rec.clone());
            msg2.add_answer(rec.clone());
            msg2.add_answer(rec.clone());

            let cache = &resolver.cache;
            assert!(cache.lookup_with_type(&name, t, |x| x).is_none());
            cache.update_from_message(&msg1, RecordSource::Forwarder);
            assert_eq!(cache.lookup_with_type(&name, t, |x| x).unwrap().get_answers().len(), 1);

            // Should replace cache with better message
            cache.update_from_message(&msg2, RecordSource::Recursive);
            assert_eq!(cache.lookup_with_type(&name, t, |x| x).unwrap().get_answers().len(), 2);

            // Should not replace cache with worse message
            cache.update_from_message(&msg1, RecordSource::Forwarder);
            assert_eq!(cache.lookup_with_type(&name, t, |x| x).unwrap().get_answers().len(), 2);

            // Should not replace cache until expiration
            cache.update_from_message(&msg1, RecordSource::Recursive);
            assert_eq!(cache.lookup_with_type(&name, t, |x| x).unwrap().get_answers().len(), 2);

            // Even better message
            cache.update_from_message(&msg1, RecordSource::Pinned);
            assert_eq!(cache.lookup_with_type(&name, t, |x| x).unwrap().get_answers().len(), 1);
        }).unwrap();
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
                source: RecordSource::Pinned,
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
