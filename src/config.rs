use std::net::{IpAddr};

use serde_yaml;

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct ServeConfig {
    pub ip: IpAddr,
    pub port: u16,
}
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub serve: ServeConfig,
    pub root_servers: Vec<IpAddr>,
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
