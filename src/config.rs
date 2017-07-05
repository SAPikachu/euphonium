use std;
use std::net::{IpAddr};
use std::time::Duration;
use std::marker::PhantomData;
use std::ops::Deref;
use std::sync::Arc;
use std::io;
use std::fs::File;
use std::io::{Read};
use std::collections::btree_map::Entry as BtEntry;
use std::str::FromStr;

use serde_yaml;
use serde::{Deserialize, Deserializer};
use serde::de::Error as DesError;
use yaml_rust::{Yaml, YamlLoader, YamlEmitter};

use utils::IpSet;

#[derive(Debug)]
pub struct ProxiedValue<TStorage, TValue>(TValue, PhantomData<TStorage>);
impl<TStorage, TValue> Deref for ProxiedValue<TStorage, TValue> {
    type Target = TValue;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl<TStorage, TValue> From<TValue> for ProxiedValue<TStorage, TValue> {
    fn from(val: TValue) -> Self {
        ProxiedValue(val, PhantomData)
    }
}
pub trait FromStorage<'de, TStorage> {
    fn from_storage<TDes: ?Sized + Deserializer<'de>>(storage: TStorage) -> Result<Self, TDes::Error> where Self: Sized;
}
impl<'de, TStorage, TValue> Deserialize<'de> for ProxiedValue<TStorage, TValue>
    where TStorage: Deserialize<'de>,
          TValue: FromStorage<'de, TStorage>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer<'de>,
    {
        let val = try!(TStorage::deserialize(deserializer));
        let result = try!(TValue::from_storage::<D>(val));
        Ok(ProxiedValue(result, PhantomData))
    }
}
impl<'de> FromStorage<'de, u32> for Duration {
    fn from_storage<TDes: ?Sized + Deserializer<'de>>(storage: u32) -> Result<Self, TDes::Error> {
        Ok(Duration::from_secs(storage as u64))
    }
}
impl<'de> FromStorage<'de, String> for Arc<IpSet> {
    fn from_storage<TDes: ?Sized + Deserializer<'de>>(storage: String) -> Result<Self, TDes::Error> {
        IpSet::from_file(&storage)
        .map(Arc::new)
        .map_err(|e| TDes::Error::custom(format!(
            "Failed to load IP list from {}: {}", storage, e,
        )))
    }
}
macro_attr! {
    #[derive(Clone, Copy, Debug, NewtypeDisplay!, NewtypeFrom!, NewtypeDeref!)]
    pub struct PermissionBits(u32);
}
impl<'de> FromStorage<'de, String> for PermissionBits {
    fn from_storage<TDes: ?Sized + Deserializer<'de>>(storage: String) -> Result<Self, TDes::Error> {
        u32::from_str_radix(&storage, 8)
        .map(Into::into)
        .map_err(|_| TDes::Error::custom(&format!(
            "Invalid permission bits: {}", storage,
        )))
    }
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct CacheConfig {
    pub min_cache_ttl: u32,
    pub min_response_ttl: u32,
    pub neg_cache_ttl: u32,
    pub cache_retention_time: ProxiedValue<u32, Duration>,
    pub cache_limit: usize,
    pub gc_aggressive_threshold: usize,
    pub gc_interval: ProxiedValue<u32, Duration>,
}
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct ServeConfig {
    pub ip: IpAddr,
    pub port: u16,
    pub tcp_timeout: ProxiedValue<u32, Duration>,
    pub setuid: Option<String>,
    pub setgid: Option<String>,
}
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct ForwarderConfig {
    pub servers: Vec<IpAddr>,
    pub accepted_ip_list: Option<ProxiedValue<String, Arc<IpSet>>>,
}
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct QueryConfig {
    pub timeout: ProxiedValue<u32, Duration>,
    pub trust_cname_hinting: bool,
    pub enable_dnssec: bool,
}
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct ControlConfig {
    pub sock_path: String,
    pub sock_permission: ProxiedValue<String, PermissionBits>,
}
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct InternalConfig {
    pub threads: usize,
    pub mio_notify_capacity: usize,
}
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub serve: ServeConfig,
    pub root_servers: Vec<IpAddr>,
    pub cache: CacheConfig,
    pub forwarders: Vec<ForwarderConfig>,
    pub query: QueryConfig,
    pub control: ControlConfig,
    pub internal: InternalConfig,
}

const DEFAULT_CONFIG: &'static str = include_str!("../extra/config-default.yaml");
impl Default for Config {
    fn default() -> Self {
        serde_yaml::from_str(DEFAULT_CONFIG).expect("Default config should never fail")
    }
}
fn merge_yaml(base: Yaml, input: Yaml) -> Yaml {
    let input = if let Yaml::Hash(hash) = input {
        hash
    } else {
        return input
    };
    let mut target = if let Yaml::Hash(base_hash) = base {
        base_hash
    } else {
        return Yaml::Hash(input)
    };
    for (k, v) in input {
        match target.entry(k) {
            BtEntry::Vacant(e) => { e.insert(v); },
            BtEntry::Occupied(mut e) => {
                let old = e.insert(Yaml::Null);
                e.insert(merge_yaml(old, v));
            },
        };
    }
    Yaml::Hash(target)
}
fn merge_config_values(user_values: Yaml) -> Yaml {
    merge_yaml(
        YamlLoader::load_from_str(DEFAULT_CONFIG).unwrap().into_iter().next().unwrap(),
        user_values,
    )
}
impl Config {
    pub fn from_file(path: &str) -> io::Result<Self> {
        let mut file = try!(File::open(path));
        let mut buffer = String::new();
        try!(file.read_to_string(&mut buffer));
        Self::from_str(&buffer)
    }
}
impl FromStr for Config {
    type Err = io::Error;
    fn from_str(content: &str) -> std::result::Result<Self, Self::Err> {
        let parsed_yaml_docs = try!(
            YamlLoader::load_from_str(content)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
        );
        if parsed_yaml_docs.len() != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Config file must contain exactly one YAML dictionary",
            ));
        }
        let merged = merge_config_values(parsed_yaml_docs.into_iter().next().unwrap());
        let mut out_str = String::new();
        {
            let mut emitter = YamlEmitter::new(&mut out_str);
            emitter.dump(&merged).unwrap(); // dump the YAML object to a String
        }
        serde_yaml::from_str(&out_str)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_default_config() {
        Config::default();
    }
    #[test]
    fn test_merged_config() {
        let config_file = r#"---
serve:
    ip: "1.1.1.1"

forwarders:
    - servers:
        - "1.2.3.4"
        "#;
        let config = Config::from_str(config_file).unwrap();
        let default_config = Config::default();
        assert_eq!(config.serve.ip, "1.1.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(config.serve.port, default_config.serve.port);
        assert_eq!(config.forwarders.len(), 1);
        assert_eq!(config.forwarders[0].servers[0], "1.2.3.4".parse::<IpAddr>().unwrap());
    }
}
