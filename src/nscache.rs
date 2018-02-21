use std::time::{SystemTime, Duration};
use std::collections::HashMap;
use std::sync::Arc;
use std::ops::Deref;
use std::net::IpAddr;
use std::cmp::{max, min};

use mioco::sync::Mutex;
use trust_dns::rr::{Name};

use cache::{GcMode, CacheCommon, CacheCommonGc, IsGcEligible};
use config::Config;

const MAX_NS_TTL: u64 = 60 * 60 * 24;
const MIN_NS_TTL: u64 = 60 * 15;

// For testing
// const MAX_NS_TTL: u64 = 9;
// const MIN_NS_TTL: u64 = 3;

pub struct NsItem {
    pub ip: IpAddr,
    pub name: Name, // FIXME: Is this really useful?
}

pub struct NsCacheEntry {
    nameservers: HashMap<IpAddr, NsItem>,
    timestamp: SystemTime,
    ttl: Option<u64>,
    zone: Name,
}
impl IsGcEligible for NsCacheEntry {
    fn is_gc_eligible(&self, mode: GcMode) -> bool {
        if self.ttl.is_none() {
            return false;
        }
        match mode {
            GcMode::Normal => self.is_expired(),
            GcMode::Aggressive => self.is_expired() || self.zone.len() > 2,
        }
    }
}
impl NsCacheEntry {
    fn new(zone: Name) -> Self {
        NsCacheEntry {
            zone: zone,
            nameservers: Default::default(),
            timestamp: SystemTime::now(),
            ttl: Some(MAX_NS_TTL),
        }
    }
    pub fn to_addrs(&self) -> Vec<IpAddr> {
        self.nameservers.keys().cloned().collect()
    }
    pub fn is_empty(&self) -> bool {
        self.nameservers.is_empty()
    }
    /// Prevent this entry from expiring
    pub fn pin(&mut self) {
        self.ttl = None;
    }
    pub fn is_pinned(&self) -> bool {
        self.ttl.is_none()
    }
    pub fn add_ns(&mut self, ip: IpAddr, domain: Name, ttl: Option<u64>) {
        if self.is_pinned() {
            warn!("Attempting to modify pinned entry {}", domain);
            return;
        }
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
    pub fn get_zone(&self) -> &Name {
        &self.zone
    }
}
#[cfg_attr(test, derive(Default))]
pub struct NsCachePlain {
    entries: HashMap<Name, NsCacheEntry>,
    config: Arc<Config>,
}
impl CacheCommon<Name, NsCacheEntry> for NsCachePlain {
    fn get_records(&self) -> &HashMap<Name, NsCacheEntry> {
        &self.entries
    }
    fn get_mut_records(&mut self) -> &mut HashMap<Name, NsCacheEntry> {
        &mut self.entries
    }
    fn get_config(&self) -> &Config {
        &self.config
    }
    fn name() -> &'static str { "NsCache" }
}
impl NsCachePlain {
    pub fn new(config: Arc<Config>) -> Self {
        NsCachePlain {
            entries: Default::default(),
            config: config,
        }
    }
    pub fn lookup(&self, name: &Name) -> Option<&NsCacheEntry> {
        self.entries.get(name)
    }
    pub fn lookup_or_insert(&mut self, name: &Name) -> &mut NsCacheEntry {
        self.entries.entry(name.clone()).or_insert_with(|| NsCacheEntry::new(name.clone()))
    }
}
pub struct NsCache {
    inst: Mutex<NsCachePlain>,
}
impl NsCache {
    pub fn new(config: Arc<Config>) -> Self {
        NsCache {
            inst: Mutex::new(NsCachePlain::new(config))
        }
    }
    pub fn gc(&self) {
        let mut guard = self.lock().unwrap();
        guard.gc();
    }
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
        self.lookup_recursive_with_filter(name, |_| true)
    }
    pub fn lookup_recursive_with_filter<F>(&self, name: &Name, predicate: F) -> Vec<IpAddr> where F: Fn(&NsCacheEntry) -> bool {
        let guard = self.lock().unwrap();
        let mut cur = name.clone();
        loop {
            match guard.lookup(&cur) {
                Some(x) if !x.is_expired() && !x.is_empty() => {
                    use itertools::Itertools;
                    debug!("Found NS for {} at {}, ({})", name, cur, x.to_addrs().iter().map(|addr| addr.to_string()).join(", "));
                    if cur.is_root() || predicate(x) {
                        return x.to_addrs();
                    }
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
#[cfg(test)]
impl Default for NsCache {
    fn default() -> Self {
        NsCache {
            inst: Mutex::new(Default::default()),
        }
    }
}
impl Deref for NsCache {
    type Target = Mutex<NsCachePlain>;

    fn deref(&self) -> &Self::Target {
        &self.inst
    }
}
