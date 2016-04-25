use std::time::SystemTime;
use std::collections::HashMap;
use std::sync::Arc;
use std::ops::Deref;

use mioco::sync::Mutex;
use trust_dns::rr::{Name, RecordType};
use trust_dns::op::Message;

use utils::MessageExt;

pub type Key = Name;
pub struct RecordTypeEntry {
    message: Option<Message>,
    expiration: Option<SystemTime>,
}
pub struct EntryPlain {
    records: HashMap<RecordType, RecordTypeEntry>,
}
impl EntryPlain {
    pub fn lookup(&self, t: RecordType) -> Option<&Message> {
        self.records.get(&t).map_or(None, |x| x.message.as_ref())
    }
    pub fn update(&mut self, msg: &Message) {
        // TODO: Validate message before updating
        // TODO: Expiration
        let mut cached = Message::new();
        cached.copy_resp_from(msg);
        self.records.insert(msg.get_queries()[0].get_query_type(), RecordTypeEntry {
            message: Some(cached),
            expiration: None,
        });
    }
}
pub type EntryInst = Arc<Mutex<EntryPlain>>;
pub struct CachePlain {
    entries: HashMap<Key, Entry>,
}
pub type CacheInst = Mutex<CachePlain>; 

impl CachePlain {
    pub fn lookup(&mut self, key: Key) -> Entry {
        self.entries.entry(key).or_insert_with(Entry::default).clone()
    }
}
pub struct Cache {
    inst: CacheInst,
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
impl Deref for Cache {
    type Target = Mutex<CachePlain>;

    fn deref(&self) -> &Self::Target {
        &self.inst
    }
}
#[derive(Clone)]
pub struct Entry {
    inst: EntryInst,
}
impl Default for Entry {
    fn default() -> Entry {
        Entry {
            inst: Arc::new(Mutex::new(EntryPlain {
                records: HashMap::new(),
            }))
        }
    }
}
impl Deref for Entry {
    type Target = Mutex<EntryPlain>;

    fn deref(&self) -> &Self::Target {
        self.inst.deref()
    }
}
