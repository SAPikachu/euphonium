use std::net::{IpAddr, Ipv6Addr, AddrParseError};
use std::io;
use std::num::ParseIntError;
use std::fs::File;
use std::io::{BufReader, BufRead};
use std::fmt::{Formatter, Debug, Error as FmtError};

use treebitmap::{IpLookupTable, IpLookupTableOps};
use itertools::Itertools;

quick_error! {
    #[derive(Debug)]
    pub enum Error {
        Io(err: io::Error) {
            from()
            from(kind: io::ErrorKind) -> (io::Error::new(kind, "Io"))
            description(err.description())
            display("{}", err)
        }
        InvalidEntry {
            description("The entry is not in correct format")
        }
        InvalidMaskLen {
            description("Mask length is not valid")
        }
        AddrParse(err: AddrParseError) {
            from()
            description(err.description())
        }
        PortParse(err: ParseIntError) {
            from()
            description(err.description())
        }
    }
}

pub struct IpSet {
    table: IpLookupTable<Ipv6Addr, ()>,
}
impl Debug for IpSet {
    fn fmt(&self, f: &mut Formatter) -> Result<(), FmtError> {
        write!(f, "IpSet ({} nodes, {} results)",
               self.table.mem_usage().0, self.table.mem_usage().1)
    }
}
impl IpSet {
    pub fn from_file(path: &str) -> Result<Self, Error> {
        let file = try!(File::open(path));
        let mut reader = BufReader::new(file);
        let mut buffer = String::new();
        let mut ret = IpSet::default();
        while try!(reader.read_line(&mut buffer)) > 0 {
            {
                let trimmed = buffer.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                try!(ret.add_entry_str(trimmed));
            }
            buffer.clear();
        }
        Ok(ret)
    }
    pub fn add_entry(&mut self, addr: IpAddr, masklen: u32) -> Result<(), Error> {
        match addr {
            IpAddr::V4(v4) => {
                self.add_entry(IpAddr::V6(v4.to_ipv6_mapped()), masklen + 96)
            },
            IpAddr::V6(v6) => {
                if masklen > 128 {
                    return Err(Error::InvalidMaskLen);
                }
                self.table.insert(v6, masklen, ());
                Ok(())
            },
        }
    }
    pub fn add_entry_str(&mut self, s: &str) -> Result<(), Error> {
        let parts = s.trim().split('/').collect_vec();
        if parts.len() != 2 {
            return Err(Error::InvalidEntry);
        }
        let ip: IpAddr = try!(parts[0].parse());
        let masklen: u32 = try!(parts[1].parse());
        self.add_entry(ip, masklen)
    }
    pub fn test(&self, addr: IpAddr) -> bool {
        let v6addr = match addr {
            IpAddr::V4(v4) => v4.to_ipv6_mapped(),
            IpAddr::V6(v6) => v6,
        };
        self.table.longest_match(v6addr).is_some()
    }
}
impl Default for IpSet {
    fn default() -> Self {
        IpSet {
            table: IpLookupTable::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipset() {
        let mut set = IpSet::default();
        set.add_entry("8.8.0.0".parse().unwrap(), 16).unwrap();
        set.add_entry_str("9.9.0.0/24").unwrap();
        set.add_entry_str("1.2.3.4/32").unwrap();
        set.add_entry("2404:6800:4004:800::".parse().unwrap(), 64).unwrap();
        set.add_entry_str("1111::/24").unwrap();
        set.add_entry_str("6666::/128").unwrap();
        
        assert!(set.add_entry("8.8.8.8".parse().unwrap(), 33).is_err());
        assert!(set.add_entry("1111::".parse().unwrap(), 129).is_err());
        assert!(set.add_entry_str("8.8.8.8/33").is_err());
        assert!(set.add_entry_str("8.8.8.8").is_err());
        assert!(set.add_entry_str("8.8.8.8.8").is_err());
        assert!(set.add_entry_str("ObviouslyInvalid").is_err());
        assert!(set.add_entry_str("1234::/129").is_err());

        assert!(set.test("8.8.8.8".parse().unwrap()));
        assert!(set.test("9.9.0.9".parse().unwrap()));
        assert!(set.test("1.2.3.4".parse().unwrap()));
        assert!(!set.test("9.9.9.9".parse().unwrap()));
        assert!(!set.test("1.1.1.1".parse().unwrap()));
        assert!(!set.test("1.2.3.7".parse().unwrap()));
        assert!(set.test("2404:6800:4004:800::2004".parse().unwrap()));
        assert!(set.test("1111::1".parse().unwrap()));
        assert!(set.test("6666::".parse().unwrap()));
        assert!(!set.test("404:6800:4004:800::2004".parse().unwrap()));
        assert!(!set.test("1:2:3:4::".parse().unwrap()));
    }
}
