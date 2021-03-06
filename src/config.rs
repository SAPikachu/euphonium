use linked_hash_map::Entry as BtEntry;
use std;
use std::fs::File;
use std::io;
use std::io::Read;
use std::marker::PhantomData;
use std::net::{IpAddr, SocketAddr};
use std::ops::Deref;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use trust_dns_client::rr::DNSClass;

use serde::de::Error as DesError;
use serde::{Deserialize, Deserializer};
use serde_yaml;
use trust_dns_proto::rr::{Name, RecordSet, RecordType};
use yaml_rust::{Yaml, YamlEmitter, YamlLoader};

use crate::utils::IpSet;

pub trait Validator<T> {
    fn validate(val: &T) -> Result<(), String>;
}
impl<T> Validator<T> for () {
    fn validate(_: &T) -> Result<(), String> {
        Ok(())
    }
}
#[derive(Debug)]
pub struct NoRootName;
impl Validator<Name> for NoRootName {
    fn validate(val: &Name) -> Result<(), String> {
        if val.is_root() {
            return Err("Root domain is not allowed".into());
        }
        Ok(())
    }
}
#[derive(Debug)]
pub struct ProxiedValue<TStorage, TValue, TValidator: Validator<TValue> = ()>(
    TValue,
    PhantomData<TStorage>,
    PhantomData<TValidator>,
);
impl<TStorage, TValue, TValidator: Validator<TValue>> Deref
    for ProxiedValue<TStorage, TValue, TValidator>
{
    type Target = TValue;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl<TStorage, TValue, TValidator: Validator<TValue>> From<TValue>
    for ProxiedValue<TStorage, TValue, TValidator>
{
    fn from(val: TValue) -> Self {
        ProxiedValue(val, PhantomData, PhantomData)
    }
}
pub trait FromStorage<'de, TStorage> {
    fn from_storage<TDes: ?Sized + Deserializer<'de>>(
        storage: &TStorage,
    ) -> Result<Self, TDes::Error>
    where
        Self: Sized;
}
impl<'de, TStorage, TValue, TValidator> Deserialize<'de>
    for ProxiedValue<TStorage, TValue, TValidator>
where
    TStorage: Deserialize<'de> + std::fmt::Display,
    TValue: FromStorage<'de, TStorage>,
    TValidator: Validator<TValue>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let val = (TStorage::deserialize(deserializer))?;
        let result = (TValue::from_storage::<D>(&val))?;
        TValidator::validate(&result)
            .map_err(|e| D::Error::custom(format!("Invalid value {}: {}", val, e)))?;
        Ok(result.into())
    }
}
impl<'de> FromStorage<'de, u32> for Duration {
    fn from_storage<TDes: ?Sized + Deserializer<'de>>(storage: &u32) -> Result<Self, TDes::Error> {
        Ok(Duration::from_secs(*storage as u64))
    }
}
impl<'de> FromStorage<'de, String> for Arc<IpSet> {
    fn from_storage<TDes: ?Sized + Deserializer<'de>>(
        storage: &String,
    ) -> Result<Self, TDes::Error> {
        IpSet::from_file(&storage).map(Arc::new).map_err(|e| {
            TDes::Error::custom(format!("Failed to load IP list from {}: {}", storage, e,))
        })
    }
}
impl<'de> FromStorage<'de, String> for Name {
    fn from_storage<TDes: ?Sized + Deserializer<'de>>(
        storage: &String,
    ) -> Result<Self, TDes::Error> {
        Name::parse(&storage, Some(&Name::root())).map_err(|e| {
            TDes::Error::custom(format!("Failed to parse domain name {}: {}", storage, e,))
        })
    }
}
impl<'de> FromStorage<'de, String> for RecordSet {
    fn from_storage<TDes: ?Sized + Deserializer<'de>>(
        storage: &String,
    ) -> Result<Self, TDes::Error> {
        use trust_dns_client::serialize::txt::{Lexer, Parser};
        let mut storage = storage.clone();
        storage += "\n";
        let lexer = Lexer::new(&storage);
        let (_, rrsets) = Parser::new()
            .parse(lexer, Some(Name::root()), Some(DNSClass::IN))
            .map_err(|e| {
                TDes::Error::custom(format!("Failed to parse local record {}: {}", storage, e,))
            })?;
        if rrsets.len() != 1 {
            return Err(TDes::Error::custom(format!(
                "Failed to parse local record {}: Each entry must contain exactly one record set, instead of {}", storage, rrsets.len(),
            )));
        }
        let rrset = rrsets.into_iter().next().unwrap().1;
        #[allow(deprecated)]
        if rrset.iter().len() == 0 {
            return Err(TDes::Error::custom(format!(
                "Failed to parse local record {}: No record in entry",
                storage,
            )));
        }
        #[allow(deprecated)]
        if rrset.record_type() == RecordType::CNAME && rrset.iter().len() != 1 {
            return Err(TDes::Error::custom(format!(
                "Failed to parse local record {}: CNAME entry must contain exactly one record",
                storage,
            )));
        }
        Ok(rrset)
    }
}
macro_attr! {
    #[derive(Clone, Copy, Debug, NewtypeDisplay!, NewtypeFrom!, NewtypeDeref!)]
    pub struct PermissionBits(u32);
}
impl<'de> FromStorage<'de, String> for PermissionBits {
    fn from_storage<TDes: ?Sized + Deserializer<'de>>(
        storage: &String,
    ) -> Result<Self, TDes::Error> {
        u32::from_str_radix(&storage, 8)
            .map(Into::into)
            .map_err(|_| TDes::Error::custom(&format!("Invalid permission bits: {}", storage,)))
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
#[derive(Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum IpWithOptionalPort {
    WithPort(SocketAddr),
    NoPort(IpAddr),
}
impl FromStr for IpWithOptionalPort {
    type Err = std::net::AddrParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse()
            .map(IpWithOptionalPort::NoPort)
            .or_else(|_| s.parse().map(IpWithOptionalPort::WithPort))
    }
}
impl IpWithOptionalPort {
    pub fn into_socketaddr(self, default_port: u16) -> SocketAddr {
        match self {
            IpWithOptionalPort::WithPort(x) => x,
            IpWithOptionalPort::NoPort(x) => SocketAddr::new(x, default_port),
        }
    }
}
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct ForwardZoneConfig {
    pub zone: ProxiedValue<String, Name>,
    pub server: IpWithOptionalPort,
}
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub serve: ServeConfig,
    pub root_servers: Vec<IpAddr>,
    pub cache: CacheConfig,
    #[serde(default)]
    pub forwarders: Vec<ForwarderConfig>,
    pub query: QueryConfig,
    pub control: ControlConfig,
    pub internal: InternalConfig,
    #[serde(default)]
    pub forward_zones: Vec<ForwardZoneConfig>,
    #[serde(default)]
    pub local_records: Vec<ProxiedValue<String, RecordSet>>,
    #[serde(default)]
    include: Option<Vec<String>>, // Placeholder
}

const DEFAULT_CONFIG: &'static str = include_str!("../extra/config-default.yaml");
impl Default for Config {
    fn default() -> Self {
        serde_yaml::from_str(DEFAULT_CONFIG).expect("Default config should never fail")
    }
}
fn merge_yaml(base: Yaml, input: Yaml) -> Yaml {
    if input == Yaml::Null {
        return base;
    }
    if let Yaml::Array(array_input) = input {
        if array_input[0] == Yaml::String("-- APPEND --".into()) {
            let mut new_array: Vec<Yaml> = Default::default();
            if let Yaml::Array(array_base) = base {
                new_array.extend(array_base);
            }
            new_array.extend(array_input.into_iter().skip(1));
            return Yaml::Array(new_array);
        } else {
            return Yaml::Array(array_input);
        }
    }
    let input = if let Yaml::Hash(hash) = input {
        hash
    } else {
        return input;
    };
    let mut target = if let Yaml::Hash(base_hash) = base {
        base_hash
    } else {
        return Yaml::Hash(input);
    };
    for (k, v) in input {
        match target.entry(k) {
            BtEntry::Vacant(e) => {
                e.insert(v);
            }
            BtEntry::Occupied(mut e) => {
                let old = e.insert(Yaml::Null);
                e.insert(merge_yaml(old, v));
            }
        };
    }
    Yaml::Hash(target)
}
fn merge_config_values(user_values: Yaml) -> Yaml {
    merge_yaml(
        YamlLoader::load_from_str(DEFAULT_CONFIG)
            .unwrap()
            .into_iter()
            .next()
            .unwrap(),
        user_values,
    )
}
fn read_file(path: &str) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut buffer = String::new();
    file.read_to_string(&mut buffer)?;
    Ok(buffer)
}
fn parse_yaml(content: &str) -> io::Result<Yaml> {
    let parsed_yaml_docs = (YamlLoader::load_from_str(content)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)))?;
    if parsed_yaml_docs.len() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Config file must contain exactly one YAML dictionary",
        ));
    }
    Ok(parsed_yaml_docs[0].clone())
}
impl Config {
    pub fn from_file(path: &str) -> io::Result<Self> {
        Self::from_str(&read_file(path)?)
    }
}
impl FromStr for Config {
    type Err = io::Error;
    fn from_str(content: &str) -> std::result::Result<Self, Self::Err> {
        let parsed_yaml_doc = parse_yaml(content)?;
        let mut merged = merge_config_values(parsed_yaml_doc);
        let err = |msg| (io::Error::new(io::ErrorKind::InvalidData, msg));
        if let Some(vec) = merged["include"].as_vec().map(|x| (*x).clone()) {
            for elem in &vec {
                if let Some(s) = elem.as_str() {
                    let content = read_file(s)
                        .map_err(|e| err(format!("Failed to read included file {}: {}", s, e)))?;
                    let doc = parse_yaml(&content)
                        .map_err(|e| err(format!("Failed to parse included file {}: {}", s, e)))?;
                    merged = merge_yaml(merged, doc);
                } else {
                    return Err(err(format!("Invalid data in include list: {:?}", elem)));
                }
            }
        }
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
    use std::fs::{remove_file, File};
    use std::io::Write;
    use std::net::IpAddr;
    use trust_dns_proto::rr::RecordType;

    #[test]
    fn test_default_config() {
        Config::default();
    }
    #[test]
    fn test_local_records() {
        let config_file = r#"---
local_records:
    - abc.test IN 1 A 1.2.3.4
    - def.xxx IN 15 CNAME abc.test
        "#;
        let config = Config::from_str(config_file).unwrap();
        assert_eq!(config.local_records.len(), 2);
        assert_eq!(
            config.local_records[0].name(),
            &Name::parse("abc.test", Some(&Name::root())).unwrap()
        );
        assert_eq!(config.local_records[0].record_type(), RecordType::A);
        assert_eq!(
            config.local_records[1].name(),
            &Name::parse("def.xxx", Some(&Name::root())).unwrap()
        );
        assert_eq!(config.local_records[1].record_type(), RecordType::CNAME);
    }
    #[test]
    fn test_no_root() {
        let config_file = r#"---
serve:
    ip: "1.1.1.1"

forwarders:
    - servers:
        - "1.2.3.4"

forward_zones:
    - zone: .
      server: 1.2.3.4
    - zone: test
      server: 5.6.7.8
        "#;
        Config::from_str(config_file).unwrap();
    }
    #[test]
    fn test_merged_config() {
        let config_file = r#"---
serve:
    ip: "1.1.1.1"

forwarders:
    - servers:
        - "1.2.3.4"

forward_zones:
    - zone: rg
      server: 1.2.3.4
    - zone: test
      server: 5.6.7.8:12345
        "#;
        let config = Config::from_str(config_file).unwrap();
        let default_config = Config::default();
        assert_eq!(config.serve.ip, "1.1.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(config.serve.port, default_config.serve.port);
        assert_eq!(config.forwarders.len(), 1);
        assert_eq!(
            config.forwarders[0].servers[0],
            "1.2.3.4".parse::<IpAddr>().unwrap()
        );
    }
    #[test]
    fn test_empty_include() {
        const INCLUDE_PATH: &str = "/tmp/c4683e82-9f96-47d3-afaf-c9823c185734";
        let included_file = r#"---

        "#;
        {
            File::create(INCLUDE_PATH)
                .unwrap()
                .write_all(included_file.as_bytes())
                .unwrap();
        }
        Config::from_str(&format!("---\n\ninclude: [\"{}\"]", INCLUDE_PATH)).unwrap();
        remove_file(INCLUDE_PATH).ok();
    }
    #[test]
    fn test_included_config() {
        const INCLUDE_PATH: &str = "/tmp/7f326c2f-9743-4c77-8c5f-136d8d6738d4";
        let included_file = r#"---
serve:
    ip: "1.1.1.1"

forwarders:
    - servers:
        - "1.2.3.4"
        "#;
        {
            File::create(INCLUDE_PATH)
                .unwrap()
                .write_all(included_file.as_bytes())
                .unwrap();
        }
        let config = Config::from_str(&format!("---\n\ninclude: [\"{}\"]", INCLUDE_PATH)).unwrap();
        remove_file(INCLUDE_PATH).ok();
        let default_config = Config::default();
        assert_eq!(config.serve.ip, "1.1.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(config.serve.port, default_config.serve.port);
        assert_eq!(config.forwarders.len(), 1);
        assert_eq!(
            config.forwarders[0].servers[0],
            "1.2.3.4".parse::<IpAddr>().unwrap()
        );
    }
}
