use std::time::SystemTime;
use std::collections::HashMap;
use std::sync::Arc;
use std::ops::Deref;
use std::net::IpAddr;

use mioco::sync::Mutex;
use trust_dns::rr::{Name, RecordType};
use trust_dns::op::Message;

use utils::MessageExt;

pub struct NsItem {
    pub ip: IpAddr,
}
#[derive(Default)]
pub struct NsCacheEntry {
    pub nameservers: HashMap<Name, NsItem>,
}
impl NsCacheEntry {
    pub fn to_addrs(&self) -> Vec<IpAddr> {
        self.nameservers.values().map(|x| x.ip).collect()
    }
}
#[derive(Default)]
pub struct NsCachePlain {
    entries: HashMap<Name, NsCacheEntry>,
}
impl NsCachePlain {
    pub fn lookup(&self, name: &Name) -> Option<&NsCacheEntry> {
        self.entries.get(name)
    }
}
pub struct NsCache {
    inst: Mutex<NsCachePlain>,
}
impl NsCache {
    pub fn lookup_recursive(&self, name: &Name) -> Vec<IpAddr> {
        let guard = self.lock().unwrap();
        let mut cur = name.clone();
        loop {
            match guard.lookup(&cur) {
                Some(x) => { return x.to_addrs(); },
                None => {
                    assert!(!cur.is_root());
                    cur = cur.base_name();
                }
            }
        }
    }
}
impl Default for NsCache {
    fn default() -> Self {
        NsCache {
            inst: Mutex::new(NsCachePlain {
                entries: HashMap::new(),
            }),
        }
    }
}
impl Deref for NsCache {
    type Target = Mutex<NsCachePlain>;

    fn deref(&self) -> &Self::Target {
        &self.inst
    }
}
