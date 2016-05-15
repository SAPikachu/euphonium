use std::net::{IpAddr};
use std::time::Duration;
use std::marker::PhantomData;
use std::ops::Deref;

use serde_yaml;
use serde::{Deserialize, Deserializer};

#[derive(Debug)]
pub struct ProxiedValue<TStorage, TValue>(TValue, PhantomData<TStorage>);
impl<TStorage, TValue> Deref for ProxiedValue<TStorage, TValue> {
    type Target = TValue;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
pub trait FromStorage<TStorage> {
    fn from_storage<TDes: ?Sized + Deserializer>(storage: TStorage) -> Result<Self, TDes::Error> where Self: Sized;
}
impl<TStorage, TValue> Deserialize for ProxiedValue<TStorage, TValue>
    where TStorage: Deserialize,
          TValue: FromStorage<TStorage>,
{
    fn deserialize<D>(deserializer: &mut D) -> Result<Self, D::Error>
        where D: Deserializer,
    {
        let val = try!(TStorage::deserialize(deserializer));
        let result = try!(TValue::from_storage::<D>(val));
        Ok(ProxiedValue(result, PhantomData))
    }
}
impl FromStorage<u32> for Duration {
    fn from_storage<TDes: ?Sized + Deserializer>(storage: u32) -> Result<Self, TDes::Error> {
        Ok(Duration::from_secs(storage as u64))
    }
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct CacheConfig {
    pub min_cache_ttl: u32,
    pub min_response_ttl: u32,
}
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct ServeConfig {
    pub ip: IpAddr,
    pub port: u16,
}
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct ForwarderConfig {
    pub servers: Vec<IpAddr>,
    pub accepted_ip_list: Option<String>,
}
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct QueryConfig {
    pub timeout: ProxiedValue<u32, Duration>,
}
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub serve: ServeConfig,
    pub root_servers: Vec<IpAddr>,
    pub cache: CacheConfig,
    pub forwarders: Vec<ForwarderConfig>,
    pub query: QueryConfig,
}

const DEFAULT_CONFIG: &'static str = include_str!("../extra/config-default.yaml");
impl Default for Config {
    fn default() -> Self {
        serde_yaml::from_str(DEFAULT_CONFIG).expect("Default config should never fail")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        Config::default();
    }
}
