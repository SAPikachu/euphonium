use std::time::{SystemTime, Duration, Instant};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::cmp::{min, max};
use std::hash::Hash;

use mioco;
use mioco::sync::{Mutex};
use mioco::sync::mpsc::{Sender};
use trust_dns::rr::{Name, RecordType, Record, DNSClass};
use trust_dns::op::{Message, OpCode, MessageType, ResponseCode, Query};
use parking_lot::Mutex as PlMutex;
use itertools::Itertools;
use time::Duration as ChDuration;

use utils::{MessageExt, AsDisplay};
use config::Config;

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Key(Name, RecordType);
impl<'a> From<&'a Query> for Key {
    fn from(q: &'a Query) -> Self {
        assert!(q.get_query_class() == DNSClass::IN);
        Key(q.get_name().clone(), q.get_query_type())
    }
}
impl From<Query> for Key {
    fn from(q: Query) -> Self {
        (&q).into()
    }
}

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
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum GcMode {
    Normal,
    Aggressive,
}
#[cfg_attr(test, derive(Default))]
struct CacheSharedData {
    // Use parking_lot::Mutex here because its overhead without contention is minimal
    expiration_notifier: Option<PlMutex<Sender<Query>>>,
    global_expiration_counter: Arc<AtomicUsize>,
    config: Arc<Config>,
}
pub struct RecordEntry {
    message: Message,
    expiration: Option<SystemTime>,
    ttl: TtlMode,
    expiration_notified: AtomicBool,
    source: RecordSource,
    record_expiration_counter: usize,
    shared: Arc<CacheSharedData>,
}
pub trait IsGcEligible {
    fn is_gc_eligible(&self, mode: GcMode) -> bool;
}
impl IsGcEligible for RecordEntry {
    fn is_gc_eligible(&self, mode: GcMode) -> bool {
        let exp = match self.expiration {
            Some(exp) => exp,
            None => return false,
        };
        if self.expiration_notified.load(Ordering::Relaxed) {
            return false;
        }
        let is_important_query = [RecordType::A, RecordType::AAAA].contains(
            &self.message.get_queries()[0].get_query_type()
        );
        let is_useful_resp = self.message.get_response_code() == ResponseCode::NoError &&
            !self.message.get_answers().is_empty();
        if mode == GcMode::Aggressive && (!is_important_query || !is_useful_resp) {
            return true;
        }
        if !self.is_expired() {
            return false;
        }
        if mode == GcMode::Aggressive {
            // Delete all expired entries in aggressive mode
            return true;
        }
        if !is_useful_resp {
            // Delete all expired entries that are not useful
            return true;
        }
        if &SystemTime::now() > &(exp + *self.shared.config.cache.cache_retention_time) {
            return true;
        }
        false
    }
}
impl RecordEntry {
    fn maybe_notify_expiration(&self) {
        let sender_locked = match self.shared.expiration_notifier {
            None => return,
            Some(ref s) => s,
        };
        if !self.is_expired() {
            return;
        }
        if self.expiration_notified.load(Ordering::Acquire) {
            // Already notified
            return;
        }
        if self.expiration_notified.swap(true, Ordering::AcqRel) {
            // Lost race
            return;
        }
        let q = self.message.get_queries()[0].clone();
        debug!("Entry expired: {}", q.as_disp());
        let sender = if cfg!(debug_assertions) {
            sender_locked.try_lock()
            .expect("This lock should never be contended as it won't leave the outer mutex")
        } else {
            let mut sender = sender_locked.try_lock();
            while sender.is_none() {
                warn!("Notification lock is contending");
                mioco::yield_now();
                sender = sender_locked.try_lock();
            }
            sender.unwrap()
        };
        sender.send(q.into()).is_ok();
    }
    pub fn is_expired(&self) -> bool {
        match self.expiration {
            None => false,
            Some(ref t) => {
                if self.record_expiration_counter !=
                    self.shared.global_expiration_counter.load(Ordering::Relaxed)
                {
                    true
                } else {
                    t <= &SystemTime::now()
                }
            },
        }
    }
    pub fn create_response(&self) -> Message {
        let mut ret = Message::new();
        self.fill_response(&mut ret);
        ret.add_query(self.message.get_queries()[0].clone());
        ret
    }
    pub fn fill_response(&self, msg: &mut Message) {
        self.maybe_notify_expiration();
        msg.copy_resp_with(&self.message, |rec| {
            let mut new_rec = rec.clone();
            self.adjust_ttl(&mut new_rec);
            new_rec
        });
    }
    pub fn is_authenticated(&self) -> bool {
        self.message.get_answers().iter()
        .chain(self.message.get_name_servers())
        .any(|rec| rec.get_rr_type() == RecordType::RRSIG)
    }
    pub fn get_source(&self) -> RecordSource {
        self.source
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
                        new_ttl = max(new_ttl, self.shared.config.cache.min_response_ttl);
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

#[cfg_attr(test, derive(Default))]
pub struct CachePlain {
    records: HashMap<Key, RecordEntry>,
    shared: Arc<CacheSharedData>,
}
pub type CacheInst = Mutex<CachePlain>;

pub trait CacheCommon<TKey, TValue> where TKey: Hash + Eq + PartialEq + Clone {
    fn get_records(&self) -> &HashMap<TKey, TValue>;
    fn get_mut_records(&mut self) -> &mut HashMap<TKey, TValue>;
    fn get_config(&self) -> &Config;
    fn name() -> &'static str { "Cache" }
    fn len(&self) -> usize {
        self.get_records().len()
    }
    fn is_empty(&self) -> bool {
        self.get_records().is_empty()
    }
    fn ensure_cache_limit(&mut self) {
        if self.len() > self.get_config().cache.cache_limit - 1 {
            // Remove random elements to reduce number of entries
            let num_to_remove = self.len() - self.get_config().cache.cache_limit + 1;
            let keys = self.get_records().keys().take(num_to_remove).cloned().collect_vec();
            keys.iter().foreach(|x| { self.get_mut_records().remove(x); });
        }
    }
}
pub trait CacheCommonGc<TKey, TValue> : CacheCommon<TKey, TValue>
    where TKey: Hash + Eq + PartialEq + Clone,
          TValue: IsGcEligible,
{
    fn gc_impl(&mut self, mode: GcMode) -> usize {
        let removed_keys = self.get_records().iter()
        .filter(|&(_, ref entry)| entry.is_gc_eligible(mode))
        .map(|(key, _)| key.clone())
        .collect_vec();
        removed_keys.iter().foreach(|k| { self.get_mut_records().remove(k); });
        removed_keys.len()
    }
    fn gc(&mut self) {
        let mode = {
            let conf = &self.get_config().cache;
            if self.len() * 100 / conf.cache_limit > conf.gc_aggressive_threshold {
                GcMode::Aggressive
            } else {
                GcMode::Normal
            }
        };
        let start_time = Instant::now();
        let removed = self.gc_impl(mode);
        let elapsed = ChDuration::from_std(start_time.elapsed())
        .expect("This shouldn't take too long");
        debug!("GC[{}, {:?}]: {} deleted, {} entries after GC, {} elapsed",
               Self::name(), mode, removed, self.len(), elapsed);
    }
}
impl<T, TKey, TValue> CacheCommonGc<TKey, TValue> for T
    where TKey: Hash + Eq + PartialEq + Clone,
          TValue: IsGcEligible,
          T: CacheCommon<TKey, TValue>,
{}
impl CacheCommon<Key, RecordEntry> for CachePlain {
    fn get_records(&self) -> &HashMap<Key, RecordEntry> {
        &self.records
    }
    fn get_mut_records(&mut self) -> &mut HashMap<Key, RecordEntry> {
        &mut self.records
    }
    fn get_config(&self) -> &Config {
        &self.shared.config
    }
}
impl CachePlain {
    pub fn lookup(&self, key: &Query) -> Option<&RecordEntry> {
        self.records.get(&key.into())
    }
    pub fn purge(&mut self, key: &Query) -> Option<Message> {
        self.records.remove(&key.into()).map(|entry| entry.message)
    }
    fn get_ttl_mode(&self, source: RecordSource) -> TtlMode {
        match source {
            RecordSource::Pinned => TtlMode::Original,
            RecordSource::Forwarder => TtlMode::Fixed(1),
            RecordSource::Recursive => TtlMode::Relative(SystemTime::now()),
        }
    }
    pub fn update(&mut self, msg: &Message, source: RecordSource) {
        self.ensure_cache_limit();
        assert!(msg.get_queries().len() == 1);
        let accepted_responses = [ResponseCode::NoError, ResponseCode::NXDomain];
        if !accepted_responses.contains(&msg.get_response_code()) {
            return;
        }
        let key: Key = (&msg.get_queries()[0]).into();
        if let Some(existing) = self.records.get(&key) {
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
        let min_cache_ttl = self.shared.config.cache.min_cache_ttl;
        let mut cache_ttl = max(
            min_cache_ttl,
            all_records.map(|x| x.get_ttl()).min().unwrap_or(min_cache_ttl),
        ) as u64;
        if msg.get_response_code() != ResponseCode::NoError {
            cache_ttl = min(cache_ttl, self.shared.config.cache.neg_cache_ttl as u64);
        }
        debug!("Updating cache: {} -> {} (TTL: {})",
               msg.get_queries()[0].as_disp(), msg.as_disp(), cache_ttl);
        let mut cache_msg = msg.clone_resp();
        cache_msg.add_query(msg.get_queries()[0].clone());
        let ttl_mode = self.get_ttl_mode(source);
        self.records.insert(key, RecordEntry {
            message: cache_msg,
            expiration: Some(SystemTime::now() + Duration::from_secs(cache_ttl)),
            ttl: ttl_mode,
            expiration_notified: AtomicBool::new(false),
            source: source,
            record_expiration_counter: self.shared.global_expiration_counter.load(
                Ordering::Relaxed,
            ),
            shared: self.shared.clone(),
        });
    }
}
pub struct Cache {
    inst: CacheInst,
    global_expiration_counter: Arc<AtomicUsize>,
}
pub type RcCache = Arc<Cache>;
impl Cache {
    pub fn new(notifier: Sender<Query>, config: Arc<Config>) -> Self {
        let counter = Arc::new(AtomicUsize::default());
        Cache {
            global_expiration_counter: counter.clone(),
            inst: Mutex::new(CachePlain {
                records: HashMap::new(),
                shared: Arc::new(CacheSharedData {
                    expiration_notifier: Some(PlMutex::new(notifier)),
                    global_expiration_counter: counter.clone(),
                    config: config,
                }),
            }),
        }
    }
    pub fn lookup<F, R>(&self, key: &Query, op: F) -> Option<R>
        where F: FnOnce(&RecordEntry) -> R,
    {
        self.operate(|x| x.lookup(key.into()).map(op))
    }
    pub fn fill_response(&self, msg: &mut Message) -> bool {
        let guard = self.inst.lock().expect("The mutex shouldn't be poisoned");
        let entry = guard.lookup(&msg.get_queries()[0]);
        entry.map(|e| e.fill_response(msg)).is_some()
    }
    pub fn operate<F, R>(&self, op: F) -> R
        where F: FnOnce(&mut CachePlain) -> R,
    {
        let mut guard = self.inst.lock().expect("The mutex shouldn't be poisoned");
        op(&mut *guard)
    }
    pub fn gc(&self) {
        self.operate(|x| x.gc());
    }
    pub fn update_from_message(&self, msg: &Message, source: RecordSource) {
        if cfg!(debug_assertions) {
            assert!(msg.get_op_code() == OpCode::Query);
            assert!(msg.get_message_type() == MessageType::Response);
            assert!(msg.get_queries().len() == 1);
            if !msg.get_answers().is_empty() {
                let name = msg.get_queries()[0].get_name();
                assert!(msg.get_answers().iter().any(|x| x.get_name() == name));
            }
        }
        self.operate(|x| x.update(msg, source));
    }
    pub fn expire_all(&self) {
        self.global_expiration_counter.fetch_add(1, Ordering::Relaxed);
    }
    pub fn clear(&self) {
        self.operate(|x| x.records.clear());
    }
}
#[cfg(test)]
impl Default for Cache {
    fn default() -> Self {
        let counter = Arc::new(AtomicUsize::default());
        Cache {
            global_expiration_counter: counter.clone(),
            inst: Mutex::new(CachePlain {
                records: HashMap::new(),
                shared: Arc::new(CacheSharedData {
                    expiration_notifier: None,
                    global_expiration_counter: counter.clone(),
                    config: Arc::new(Config::default()),
                }),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::*;
    use std::sync::*;
    use std::time::*;
    use trust_dns::rr::*;
    use trust_dns::op::*;
    use super::*;
    use utils::*;
    use config::*;
    use mioco;
    use ::mioco_config_start;

    fn name(raw: &str) -> Name {
        Name::parse(raw, Some(&Name::root())).unwrap()
    }
    macro_rules! add_entry {
        ($cache:ident, $name:expr, $rtyp:ident, $rcode:ident $(, [$ttl:expr, $recdata:expr])*) => {{
            let name = name($name);
            let mut q = Query::new();
            q.name(name);
            let mut msg = Message::new();
            q.query_type(RecordType::$rtyp);
            msg.message_type(MessageType::Response);
            msg.response_code(ResponseCode::$rcode);
            msg.add_query(q);
            $(
                let mut rec = Record::new();
                rec.ttl($ttl);
                rec.rr_type(RecordType::$rtyp);
                rec.rdata(RData::$rtyp($recdata));
                msg.add_answer(rec);
             )*;
            $cache.update(&msg, RecordSource::Recursive);
        }}
    }
    #[test]
    fn test_limit() {
        mioco_config_start(move || {
            let mut config = Config::default();
            config.cache.cache_retention_time = Duration::from_secs(1).into();
            config.cache.min_cache_ttl = 1;
            config.cache.cache_limit = 5;
            config.cache.gc_aggressive_threshold = 10;
            let (send, _) = mioco::sync::mpsc::channel::<Query>();
            Cache::new(send, Arc::new(config)).operate(|mut cache| {
                add_entry!(cache, "www.nonexistent1.com", A, NXDomain);
                add_entry!(cache, "www.nonexistent2.com", A, NXDomain);
                add_entry!(cache, "www.nonexistent3.com", A, NXDomain);
                add_entry!(cache, "www.nonexistent4.com", A, NXDomain);
                add_entry!(cache, "www.nonexistent5.com", A, NXDomain);
                add_entry!(cache, "www.nonexistent6.com", A, NXDomain);
                add_entry!(cache, "www.nonexistent7.com", A, NXDomain);
                add_entry!(cache, "www.nonexistent8.com", A, NXDomain);
                assert_eq!(cache.len(), 5);
            });
        }).unwrap();
    }
    #[test]
    fn test_neg_ttl() {
        mioco_config_start(move || {
            let mut config = Config::default();
            config.cache.cache_retention_time = Duration::from_secs(1).into();
            config.cache.min_cache_ttl = 1;
            config.cache.neg_cache_ttl = 1;
            let (send, _) = mioco::sync::mpsc::channel::<Query>();
            Cache::new(send, Arc::new(config)).operate(|mut cache| {
                add_entry!(cache, "www.nonexistent.com", A, NXDomain);
                assert_eq!(cache.len(), 1);
                cache.gc();
                assert_eq!(cache.len(), 1);
                mioco::sleep(Duration::from_secs(3));
                cache.gc();
                assert_eq!(cache.len(), 0);
            });
        }).unwrap();
    }
    #[test]
    fn test_gc() {
        mioco_config_start(move || {
            let mut config = Config::default();
            config.cache.cache_retention_time = Duration::from_secs(1).into();
            config.cache.min_cache_ttl = 1;
            config.cache.cache_limit = 100;
            config.cache.gc_aggressive_threshold = 10;
            let (send, _) = mioco::sync::mpsc::channel::<Query>();
            Cache::new(send, Arc::new(config)).operate(|mut cache| {
                let shared = cache.shared.clone();

                // Normal mode
                add_entry!(cache, "www.google.com", A, NoError, [1, "1.1.1.1".parse().unwrap()]);
                add_entry!(cache, "www.google.com", AAAA, NoError, [1, "1::1".parse().unwrap()]);
                add_entry!(cache, "www.google.com", CNAME, NoError, [1, name("cname")]);
                add_entry!(cache, "www.nonexistent.com", A, NXDomain);

                assert_eq!(cache.len(), 4);
                cache.gc_impl(GcMode::Normal);
                assert_eq!(cache.len(), 4);
                shared.global_expiration_counter.fetch_add(2, Ordering::Relaxed);
                cache.gc_impl(GcMode::Normal);
                assert_eq!(cache.len(), 3);
                mioco::sleep(Duration::from_secs(3));
                cache.gc_impl(GcMode::Normal);
                assert_eq!(cache.len(), 0);

                // Aggressive mode
                add_entry!(cache, "www.google.com", A, NoError, [1, "1.1.1.1".parse().unwrap()]);
                add_entry!(cache, "www.google.com", AAAA, NoError, [1, "1::1".parse().unwrap()]);
                add_entry!(cache, "www.google.com", CNAME, NoError, [1, name("cname")]);
                add_entry!(cache, "www.nonexistent.com", A, NXDomain);

                assert_eq!(cache.len(), 4);
                cache.gc_impl(GcMode::Aggressive);
                assert_eq!(cache.len(), 2);
                shared.global_expiration_counter.fetch_add(2, Ordering::Relaxed);
                cache.gc_impl(GcMode::Aggressive);
                assert_eq!(cache.len(), 0);

                // Auto mode
                add_entry!(cache, "www.google.com", A, NoError, [1, "1.1.1.1".parse().unwrap()]);
                add_entry!(cache, "www.nonexistent1.com", A, NXDomain);
                add_entry!(cache, "www.nonexistent2.com", A, NXDomain);
                add_entry!(cache, "www.nonexistent3.com", A, NXDomain);
                add_entry!(cache, "www.nonexistent4.com", A, NXDomain);
                add_entry!(cache, "www.nonexistent5.com", A, NXDomain);
                add_entry!(cache, "www.nonexistent6.com", A, NXDomain);
                add_entry!(cache, "www.nonexistent7.com", A, NXDomain);
                add_entry!(cache, "www.nonexistent8.com", A, NXDomain);
                assert_eq!(cache.len(), 9);
                cache.gc();
                assert_eq!(cache.len(), 9);
                add_entry!(cache, "www.nonexistent9.com", A, NXDomain);
                add_entry!(cache, "www.nonexistenta.com", A, NXDomain);
                cache.gc();
                assert_eq!(cache.len(), 1);
            });
        }).unwrap();
    }
    #[test]
    fn test_record_preference() {
        mioco_config_start(move || {
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

            let cache = Cache::default();
            assert!(cache.lookup(&q, |x| x.create_response()).is_none());
            cache.update_from_message(&msg1, RecordSource::Forwarder);
            assert_eq!(cache.lookup(&q, |x| x.create_response()).unwrap().get_answers().len(), 1);

            // Should replace cache with better message
            cache.update_from_message(&msg2, RecordSource::Recursive);
            assert_eq!(cache.lookup(&q, |x| x.create_response()).unwrap().get_answers().len(), 2);

            // Should not replace cache with worse message
            cache.update_from_message(&msg1, RecordSource::Forwarder);
            assert_eq!(cache.lookup(&q, |x| x.create_response()).unwrap().get_answers().len(), 2);

            // Should not replace cache until expiration
            cache.update_from_message(&msg1, RecordSource::Recursive);
            assert_eq!(cache.lookup(&q, |x| x.create_response()).unwrap().get_answers().len(), 2);

            // Even better message
            cache.update_from_message(&msg1, RecordSource::Pinned);
            assert_eq!(cache.lookup(&q, |x| x.create_response()).unwrap().get_answers().len(), 1);
        }).unwrap();
    }
    #[test]
    fn test_fill_response() {
        let cache = Cache::default();
        let mut msg = Message::new();
        msg.message_type(MessageType::Response);
        msg.op_code(OpCode::Query);
        let t = RecordType::A;
        let mut q = Query::new();
        q.name(name("www.google.com"));
        q.query_type(t);
        msg.add_query(q.clone());
        cache.update_from_message(&msg, RecordSource::Recursive);

        msg = Message::new();
        msg.add_query(q.clone());
        assert!(cache.fill_response(&mut msg));
        q.name(name("www.baidu.com"));
        msg = Message::new();
        msg.add_query(q.clone());
        assert!(!cache.fill_response(&mut msg));
        q.name(name("www.google.com"));
        q.query_type(RecordType::AAAA);
        msg = Message::new();
        msg.add_query(q.clone());
        assert!(!cache.fill_response(&mut msg));
    }
    #[test]
    fn test_cache_case_insensitivity() {
        let mut cache = CachePlain::default();
        let mut msg = Message::new();
        msg.message_type(MessageType::Response);
        msg.op_code(OpCode::Query);
        let t = RecordType::A;
        let mut q = Query::new();
        q.name(name("www.google.com"));
        q.query_type(t);
        msg.add_query(q.clone());

        cache.update(&msg, RecordSource::Recursive);
        assert!(cache.lookup(&q).is_some());
        assert!(cache.lookup(q.name(name("www.baidu.com"))).is_none());
        assert!(cache.lookup(q.name(name("wWw.goOgle.coM"))).is_some());
    }
    #[test]
    fn test_ttl_adjust() {
        mioco_config_start(move || {
            let cache = CachePlain::default();
            let min_ttl = cache.shared.config.cache.min_response_ttl;
            let mut entry = RecordEntry {
                message: Message::new(),
                expiration: None,
                ttl: TtlMode::Original,
                expiration_notified: AtomicBool::new(false),
                source: RecordSource::Pinned,
                record_expiration_counter: 0,
                shared: cache.shared.clone(),
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
