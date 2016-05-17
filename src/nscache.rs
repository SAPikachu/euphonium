use std::time::{SystemTime, Duration};
use std::collections::HashMap;
use std::sync::Arc;
use std::ops::Deref;
use std::net::IpAddr;
use std::cmp::{max, min};

use mioco::sync::Mutex;
use trust_dns::rr::{Name};

const MAX_NS_TTL: u64 = 60 * 60 * 24;
const MIN_NS_TTL: u64 = 60 * 15;

pub struct NsItem {
    pub ip: IpAddr,
    pub name: Name, // FIXME: Is this really useful?
}

pub struct NsCacheEntry {
    nameservers: HashMap<IpAddr, NsItem>,
    timestamp: SystemTime,
    ttl: Option<u64>,
}
impl Default for NsCacheEntry {
    fn default() -> Self {
        NsCacheEntry {
            nameservers: HashMap::default(),
            timestamp: SystemTime::now(),
            ttl: Some(MAX_NS_TTL),
        }
    }
}
impl NsCacheEntry {
    pub fn to_addrs(&self) -> Vec<IpAddr> {
        self.nameservers.keys().cloned().collect()
    }
    /// Prevent this entry from expiring
    pub fn pin(&mut self) {
        self.ttl = None;
    }
    pub fn add_ns(&mut self, ip: IpAddr, domain: Name, ttl: Option<u64>) {
        if self.is_expired() {
            self.nameservers.clear();
            self.timestamp = SystemTime::now();
            self.ttl = Some(MAX_NS_TTL);
        }
        self.nameservers.entry(ip).or_insert_with(move || NsItem {
            ip: ip,
            name: domain,
        });
        match self.ttl {
            None => {},
            Some(cur_ttl) => {
                self.ttl = Some(max(min(cur_ttl, ttl.unwrap_or(cur_ttl)), MIN_NS_TTL));
            },
        }
    }
    pub fn is_expired(&self) -> bool {
        match self.ttl {
            None => false,
            Some(ttl) => self.timestamp + Duration::from_secs(ttl) <= SystemTime::now(),
        }
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
    pub fn lookup_or_insert(&mut self, name: &Name) -> &mut NsCacheEntry {
        self.entries.entry(name.clone()).or_insert_with(NsCacheEntry::default)
    }
}
pub struct NsCache {
    inst: Mutex<NsCachePlain>,
}
pub type RcNsCache = Arc<NsCache>;
impl NsCache {
    pub fn update<T>(&self, auth_zone: &Name, items: T)
        where T: IntoIterator<Item=(IpAddr, Name, u64)>,
    {
        let mut guard = self.lock().unwrap();
        let entry = guard.lookup_or_insert(auth_zone);
        for (ip, name, ttl) in items {
            entry.add_ns(ip, name, Some(ttl));
        }
    }
    pub fn lookup_recursive(&self, name: &Name) -> Vec<IpAddr> {
        let guard = self.lock().unwrap();
        let mut cur = name.clone();
        loop {
            match guard.lookup(&cur) {
                Some(x) if !x.is_expired() => {
                    debug!("Found NS for {} at {}", name, cur);
                    return x.to_addrs();
                },
                Some(_) => {
                    debug!("NS for {} at {} is expired", name, cur);
                },
                None => {},
            }
            assert!(!cur.is_root());
            cur = cur.base_name();
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
// TODO: Case insensitivity, add tests
