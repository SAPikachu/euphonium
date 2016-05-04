use std::time::SystemTime;
use std::collections::HashMap;
use std::sync::Arc;
use std::ops::Deref;

use mioco::sync::Mutex;
use trust_dns::rr::{Name, RecordType};
use trust_dns::op::{Message, OpCode, MessageType, ResponseCode};

use utils::MessageExt;

pub type Key = Name;
#[derive(Default)]
pub struct RecordTypeEntry {
    message: Option<Message>,
    expiration: Option<SystemTime>,
}
#[derive(Default)]
pub struct Entry {
    records: HashMap<RecordType, RecordTypeEntry>,
}
impl Entry {
    pub fn lookup(&self, t: RecordType) -> Option<&Message> {
        self.records.get(&t).map_or(None, |x| x.message.as_ref())
    }
    pub fn update(&mut self, msg: &Message) {
        // TODO: Validate message before updating
        // TODO: Confirm that the new message is more preferable than existing one
        // TODO: Expiration
        let t = msg.get_queries()[0].get_query_type();
        if self.records.contains_key(&t) {
            return;
        }
        self.records.insert(t, RecordTypeEntry {
            message: Some(msg.clone_resp()),
            expiration: None,
        });
    }
}
#[derive(Default)]
pub struct CachePlain {
    entries: HashMap<Key, Entry>,
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
    pub fn lookup<F, R>(&self, key: &Key, op: F) -> Option<R>
        where F: FnOnce(&Entry) -> R,
    {
        let guard = self.inst.lock().expect("The mutex shouldn't be poisoned");
        guard.lookup(key).map(op)
    }
    pub fn lookup_with_type<F, R>(&self, key: &Key, t: RecordType, op: F) -> Option<R>
        where F: FnOnce(&Message) -> R,
    {
        let guard = self.inst.lock().expect("The mutex shouldn't be poisoned");
        guard.lookup(key).and_then(|entry| entry.lookup(t)).map(op)
    }
    pub fn operate<F, R>(&self, key: &Key, op: F) -> R
        where F: FnOnce(&mut Entry) -> R,
    {
        let mut guard = self.inst.lock().expect("The mutex shouldn't be poisoned");
        op(guard.lookup_or_insert(key))
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
        self.operate(name, |entry| entry.update(&msg));
    }
}
impl Default for Cache {
    fn default() -> Self {
        Cache {
            inst: Mutex::new(CachePlain {
                entries: HashMap::new(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trust_dns::rr::Name;

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
}
