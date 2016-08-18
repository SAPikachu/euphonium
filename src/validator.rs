#![cfg_attr(debug_assertions, allow(unused_imports, dead_code))]

use std::collections::HashSet;
use std::time::{UNIX_EPOCH, Duration};

use trust_dns::op::{Message, MessageType, ResponseCode, Query, OpCode, Edns};
use trust_dns::rr::{DNSClass, RecordType, Record, RData, Name};
use trust_dns::rr::rdata::{SIG, DNSKEY};
use trust_dns::rr::dnssec::{Signer, TrustAnchor};
use trust_dns::serialize::binary::{BinEncoder, BinSerializable};
use openssl::crypto::pkey::Role;
use itertools::Itertools;

use resolver::RcResolver;
use utils::Result;
use recursive::RecursiveResolver;

lazy_static! {
    static ref TRUST_ANCHOR: TrustAnchor = TrustAnchor::default();
}

#[derive(Eq, PartialEq, Debug)]
enum ValidationResult {
    NonAuthenticated,
    Authenticated,
    Bogus,
}
pub trait ResponseValidator {
    fn is_valid(&mut self, msg: &Message) -> bool;
}
pub struct DummyValidator;
impl ResponseValidator for DummyValidator {
    fn is_valid(&mut self, _: &Message) -> bool {
        true
    }
}
pub trait SubqueryResolver {
    fn resolve_sub(&self, q: Query) -> Result<Message>;
}
impl SubqueryResolver for RcResolver {
    fn resolve_sub(&self, q: Query) -> Result<Message> {
        RecursiveResolver::resolve(&q, self.clone())
    }
}
pub struct DnssecValidator<T: SubqueryResolver> {
    resolver: T,
}
impl<T: SubqueryResolver> DnssecValidator<T> {
    pub fn new(resolver: T) -> Self {
        DnssecValidator {
            resolver: resolver,
        }
    }
    fn verify_sig_time(sig: &SIG) -> bool {
        let mut cur_time = UNIX_EPOCH.elapsed()
        .unwrap_or_else(|_| Duration::new(0, 0)).as_secs() as u64;
        cur_time &= 0xffff_ffff;
        let inception = sig.get_sig_inception() as u64;
        if cur_time < inception {
            cur_time += 0x1_0000_0000;
        }
        let expiration = {
            let t = sig.get_sig_expiration() as u64;
            if t < inception {
                t + 0x1_0000_0000
            } else {
                t
            }
        };
        cur_time < expiration
    }
    fn subquery(&self, name: &Name, query_type: RecordType, class: DNSClass) -> Result<Message> {
        let mut q = Query::new();
        q.name(name.clone());
        q.query_type(query_type);
        q.query_class(class);
        self.resolver.resolve_sub(q)
    }
    fn verify_ds(&self, dnskey: &Record) -> Result<bool> {
        let (public_key, algorithm) = if let RData::DNSKEY(ref rdata) = *dnskey.get_rdata() {
            (rdata.get_public_key(), rdata.get_algorithm())
        } else {
            panic!("Invalid record type")
        };
        if TRUST_ANCHOR.contains(public_key) {
            return Ok(true);
        }
        let name = dnskey.get_name();
        if name.is_root() {
            // Avoid infinite loop
            return Ok(false);
        }
        let ds_resp = try!(self.subquery(
            dnskey.get_name(),
            RecordType::DS,
            dnskey.get_dns_class(),
        ));
        let mut buf = Vec::<u8>::new();
        {
            let mut encoder = BinEncoder::new(&mut buf);
            encoder.set_canonical_names(true);
            try!(dnskey.get_name().emit(&mut encoder));
            try!(dnskey.get_rdata().emit(&mut encoder));
        }
        Ok(ds_resp.get_answers().iter().any(|x| match *x.get_rdata() {
            RData::DS(ref ds) if ds.get_algorithm() == algorithm => {
                let hash = ds.get_digest_type().hash(&buf);
                hash == ds.get_digest()
            },
            _ => false,
        }))
    }
    fn create_verifier(key: &DNSKEY, signer_name: &Name) -> Option<Signer> {
        if key.is_revoke() {
            debug!("DNSKEY is revoked: {:?}", key);
            return None;
        }
        if !key.is_zone_key() {
            return None;
        }
        let pkey = key.get_algorithm().public_key_from_vec(key.get_public_key());
        let pkey = match pkey {
            Ok(k) => k,
            Err(e) => {
                warn!("Failed to get public key from DNSKEY: {:?}", e);
                return None
            },
        };
        if !pkey.can(Role::Verify) {
            debug!("PKey can't be used to verify: {:?}", key);
            return None;
        }
        Some(Signer::new_verifier(
            *key.get_algorithm(), pkey, signer_name.clone(),
        ))
    }
    fn calculate_dnskey_tag(key: &DNSKEY) -> u16 {
        // FIXME: This doesn't handle the special case of algorithm 1
        let mut buf = Vec::<u8>::new();
        {
            let mut encoder = BinEncoder::new(&mut buf);
            encoder.set_canonical_names(true);
            RData::DNSKEY(key.clone()).emit(&mut encoder).unwrap();
        }
        // Copied from trust-dns
        let mut ac: usize = 0;

        for (i,k) in buf.iter().enumerate() {
            ac += if i & 0x0001 == 0x0001 {
                *k as usize
            } else {
                (*k as usize) << 8
            };
        }

        ac += (ac >> 16 ) & 0xFFFF;
        (ac & 0xFFFF) as u16
    }
    fn get_delegated_dnskeys(&self, rrset: &[Record]) -> Vec<DNSKEY> {
        rrset.iter()
        .filter(|rec| self.verify_ds(rec).unwrap_or(false))
        .map(|rec| if let RData::DNSKEY(ref dnskey) = *rec.get_rdata() {
            dnskey.clone()
        } else {
            panic!("Invalid record type")
        }).collect_vec()
    }
    fn query_dnskey(&self, signer_name: &Name, rr_class: DNSClass) -> Result<Vec<DNSKEY>> {
        let mut q = Query::new();
        q.name(signer_name.clone())
        .query_class(rr_class)
        .query_type(RecordType::DNSKEY);
        let resp = try!(self.resolver.resolve_sub(q));
        Ok(resp.get_answers().iter().filter_map(|rec| match *rec.get_rdata() {
            RData::DNSKEY(ref dnskey) => Some(dnskey.clone()),
            _ => None,
        }).collect_vec())
    }
    fn verify_rrsig(&self, rrset: &[Record], rrsigs: &[SIG]) -> Result<ValidationResult> {
        assert!(!rrset.is_empty());
        let rr_name = rrset[0].get_name();
        let rr_class = rrset[0].get_dns_class();
        let rr_type = rrset[0].get_rr_type();
        if rrsigs.is_empty() {
            debug!("No RRSIG for {} {:?} {:?}", rr_name, rr_class, rr_type);
            return Ok(ValidationResult::Bogus);
        }
        debug_assert!(rrset.iter().all(|x| x.get_rr_type() == rr_type));
        debug_assert!(rrset.iter().all(|x| x.get_name() == rr_name));
        debug_assert!(rrsigs.iter().all(|x| x.get_type_covered() == rr_type));
        for sig in rrsigs {
            if !Self::verify_sig_time(sig) {
                debug!("Not in validity time ({} -> {}).",
                       sig.get_sig_inception(), sig.get_sig_expiration());
                continue;
            }
            let signer_name = sig.get_signer_name();
            // The number of labels in the RRset owner name MUST be greater than
            // or equal to the value in the RRSIG RR's Labels field.
            if rr_name.num_labels() < sig.get_num_labels() {
                debug!("Number of labels: name = {} ({}), sig = {}",
                       rr_name.num_labels(), rr_name, sig.get_num_labels());
                continue;
            }
            if !signer_name.zone_of(rr_name) {
                debug!("Signer's name ({}) is not zone of RRset owner name ({})",
                       signer_name, rr_name);
                continue;
            }
            let dnskeys = if rr_type == RecordType::DNSKEY && signer_name == rr_name {
                self.get_delegated_dnskeys(rrset)
            } else {
                try!(self.query_dnskey(signer_name, rr_class))
            };
            for key in dnskeys {
                if *key.get_algorithm() != sig.get_algorithm() {
                    continue;
                }
                let signer = match Self::create_verifier(&key, signer_name) {
                    Some(x) => x,
                    None => continue,
                };
                // Wildcard is handled in `hash_rrset`
                let rrset_hash: Vec<u8> = signer.hash_rrset(
                    rr_name, rr_class,
                    sig.get_num_labels(), sig.get_type_covered(), sig.get_algorithm(),
                    sig.get_original_ttl(), sig.get_sig_expiration(), sig.get_sig_inception(),
                    sig.get_key_tag(), signer_name, rrset,
                );
                if signer.verify(&rrset_hash, sig.get_sig()) {
                    trace!("Verified {} {:?} with {:?} (signer: {})",
                           rr_name, rr_type, key.get_algorithm(), signer_name);
                    return Ok(ValidationResult::Authenticated);
                } else {
                    debug!("Failed to verify {} {:?} ({}) with ({:?}, {}, {}) (signer: {})",
                           rr_name, rr_type, rrset.len(),
                           key.get_algorithm(), sig.get_key_tag(),
                           Self::calculate_dnskey_tag(&key), signer_name);
                }
            }
        }
        debug!("No valid RRSIG for {} {:?} {:?}", rr_name, rr_class, rr_type);
        Ok(ValidationResult::Bogus)
    }
    // Largely stolen from trust-dns
    fn verify_rrsigs(&self, msg: &Message) -> Result<ValidationResult> {
        debug_assert!(msg.get_queries().len() == 1);
        let q = &msg.get_queries()[0];
        let query_name = q.get_name();
        let query_type = q.get_query_type();
        let rrsigs = msg.get_answers().iter()
        .chain(msg.get_name_servers())
        .filter(|rr| rr.get_rr_type() == RecordType::RRSIG)
        .collect_vec();

        if rrsigs.is_empty() {
            let mut name = query_name.clone();
            if query_type == RecordType::DS && !name.is_root() {
                name = name.base_name();
            }
            let class = q.get_query_class();
            while !name.is_root() {
                let ds_resp = try!(self.subquery(&name, RecordType::DS, class));
                let have_ds = ds_resp.get_answers().iter().any(
                    |rec| *rec.get_name() == name && rec.get_rr_type() == RecordType::DS
                );
                if have_ds {
                    // Secure zone, but we got no RRSIG
                    return Ok(ValidationResult::Bogus);
                }
                let have_nsec = ds_resp.get_name_servers().iter().any(
                    |rec| match *rec.get_rdata() {
                        RData::NSEC(ref nsec) => true, // TODO
                        RData::NSEC3(ref nsec3) => true, // TODO
                        _ => false,
                    }
                );
                if have_nsec {
                    // Insecure zone
                    break;
                }
                name = name.base_name();
            }
            return Ok(ValidationResult::NonAuthenticated);
        }
        // Group the record sets by name and type
        let mut rrset_types: HashSet<(Name, RecordType)> = HashSet::new();
        msg.get_answers().iter()
        .chain(msg.get_name_servers())
        .filter(|rr| rr.get_rr_type() != RecordType::RRSIG)
        .map(|rr| (rr.get_name().clone(), rr.get_rr_type()))
        .foreach(|rr| { rrset_types.insert(rr); });

        for (name, rr_type) in rrset_types {
            let rrset = msg.get_answers().iter()
            .chain(msg.get_name_servers())
            .filter(|rr| rr.get_rr_type() == rr_type && *rr.get_name() == name)
            .cloned()
            .collect_vec();
            let rrsig = rrsigs.iter()
            .filter(|rr| *rr.get_name() == name)
            .filter_map(|rr| if let RData::SIG(ref sig) = *rr.get_rdata() {
                if sig.get_type_covered() == rr_type {
                    Some(sig.clone())
                } else {
                    None
                }
            } else {
                panic!("Unexpected RData: {:?}", rr)
            })
            .collect_vec();
            if rr_type == RecordType::NS && rrsig.is_empty() && msg.get_answers().is_empty() {
                // NS records are not signed in referral
                continue;
            }
            if try!(self.verify_rrsig(&rrset, &rrsig)) != ValidationResult::Authenticated {
                return Ok(ValidationResult::Bogus);
            }
        }
        let have_answer = msg.get_answers().iter().any(|rec| {
            (rec.get_rr_type() == query_type ||
             rec.get_rr_type() == RecordType::CNAME) &&
            rec.get_name() == query_name
        });
        if have_answer {
            return Ok(ValidationResult::Authenticated);
        }
        let is_secure_delegation = msg.get_name_servers().iter().any(|rec| {
            rec.get_rr_type() == RecordType::DS && rec.get_name().zone_of(query_name)
        });
        if is_secure_delegation {
            return Ok(ValidationResult::Authenticated);
        }
        // TODO: Verify NSEC/NSEC3
        // TODO: Handle wildcard (RFC7129)
        Ok(ValidationResult::Authenticated)
    }
    fn verify_nsec(&self, q: &Query, nsec_rrset: &[Record]) -> bool {
    }
}
impl<T: SubqueryResolver> ResponseValidator for DnssecValidator<T> {
    fn is_valid(&mut self, msg: &Message) -> bool {
        self.verify_rrsigs(msg).unwrap_or(ValidationResult::Bogus) != ValidationResult::Bogus
    }
}

#[cfg(test)]
mod tests {
    extern crate env_logger;
    use std::time::Duration;
    use trust_dns::op::*;
    use trust_dns::rr::*;
    use trust_dns::serialize::binary::*;
    use super::*;
    use ::query::query;
    use ::resolver::*;
    use ::recursive::*;
    use ::utils::MessageExt;
    use ::mioco_config_start;

    fn test_query(domain: &str) -> Message {
        let mut q = Query::new();
        q.name(Name::parse(domain, Some(&Name::root())).unwrap())
        .query_class(DNSClass::IN)
        .query_type(RecordType::A);
        query(q, "8.8.8.8".parse().unwrap(), Duration::from_secs(5)).unwrap()
    }

    #[test]
    fn test_dnssec_valid() {
        env_logger::init().is_ok();
        mioco_config_start(move || {
            let resolver = RcResolver::default();
            let mut validator = DnssecValidator::new(resolver.clone());
            let msg = test_query("sigok.verteiltesysteme.net");
            assert!(msg.get_answers().iter().any(|r| r.get_rr_type() == RecordType::RRSIG));
            assert!(validator.is_valid(&msg));
        }).unwrap();
    }
    #[test]
    fn test_dnssec_valid_rollernet() {
        env_logger::init().is_ok();
        mioco_config_start(move || {
            let resolver = RcResolver::default();
            let mut validator = DnssecValidator::new(resolver.clone());
            let msg = test_query("ns1.rollernet.us");
            assert!(validator.is_valid(&msg));
        }).unwrap();
    }
    #[test]
    fn test_dnssec_valid_rollernet3() {
        env_logger::init().is_ok();
        mioco_config_start(move || {
            let resolver = RcResolver::default();
            let mut validator = DnssecValidator::new(resolver.clone());
            let msg = test_query("nS3-i.rOllErnet.Us");
            assert!(validator.is_valid(&msg));
        }).unwrap();
    }
    #[test]
    fn test_dnssec_invalid() {
        env_logger::init().is_ok();
        mioco_config_start(move || {
            let resolver = RcResolver::default();
            let msg = test_query("sigfail.verteiltesysteme.net");
            assert!(msg.get_answers().iter().any(|r| r.get_rr_type() == RecordType::RRSIG));
            let mut validator = DnssecValidator::new(resolver.clone());
            assert!(!validator.is_valid(&msg));
        }).unwrap();
    }
    #[test]
    fn test_dnssec_integrated() {
        env_logger::init().is_ok();
        mioco_config_start(move || {
            let resolver = RcResolver::default();
            let mut q = Query::new();
            q.name(Name::parse("sigok.verteiltesysteme.net.", None).unwrap())
            .query_class(DNSClass::IN)
            .query_type(RecordType::A);
            RecursiveResolver::resolve(&q, resolver.clone()).unwrap();
            q.name(Name::parse("nS3-i.rOllErnet.Us.", None).unwrap());
            RecursiveResolver::resolve(&q, resolver.clone()).unwrap();
            q.name(Name::parse("ns1.rollernet.us.", None).unwrap());
            RecursiveResolver::resolve(&q, resolver.clone()).unwrap();
            q.name(Name::parse("sigfail.verteiltesysteme.net.", None).unwrap());
            RecursiveResolver::resolve(&q, resolver.clone()).unwrap_err();
        }).unwrap();
    }
    #[test]
    #[ignore]
    fn test_dnssec_rollernet() {
        // This test will fail after signature in the data is expired, leaving here for
        // reference only
        env_logger::init().is_ok();
        mioco_config_start(move || {
            let resolver = RcResolver::default();
            let data_str = r"
2ef9 8100
0001 0000 0005 0005 036e 7331 0972 6f6c
6c65 726e 6574 0275 7300 0001 0001 0952
4f4c 4c45 524e 4554 c01a 0002 0001 0000
1c20 0008 054e 5332 2d49 c022 c022 0002
0001 0000 1c20 0015 054e 5333 2d49 0952
4f4c 4c45 524e 4554 034e 4554 00c0 2200
0200 0100 001c 2000 0805 4e53 312d 49c0
22c0 2200 2f00 0100 0151 8000 1a0d 524f
4c4c 4552 4e45 5457 4f52 4b02 7573 0000
0620 0000 0000 03c0 2200 2e00 0100 0151
8000 9600 2f05 0200 0151 8057 c96e 9d57
a1db 4de7 5402 7573 00a2 c40a cbd5 1927
11fe 6626 fe7e 1d5f de05 531a 3c2b ac74
0686 c2e6 1271 efb9 bc72 3c08 84bf 7f99
2c0c 46e0 e58b b6b1 9b03 b125 4782 d9b1
83ee 06f4 18b3 d841 fee2 19ea 669d 8b05
0db4 9d45 7d3b 6a93 61b9 69ad 5104 8579
242f 949b 9f4e 41d6 07d2 5d85 330a 52c4
bcd9 5a71 2175 6aea 74de e939 e23f fb8a
b461 677e cf31 8883 b8c0 6d00 0100 0100
001c 2000 04d0 4ff0 14c0 6d00 1c00 0100
001c 2000 1026 07fe 7000 0000 0300 0000
0000 0000 10c0 3800 0100 0100 001c 2000
04d0 4ff1 14c0 3800 1c00 0100 001c 2000
1026 07fe 7000 0000 0400 0000 0000 0000
1000 0029 1000 0000 8000 0000
            ";
            use rustc_serialize::hex::*;
            let data = data_str.from_hex().unwrap();
            assert_eq!(data.len(), 416);
            let msg = Message::from_bytes(&data).unwrap();
            debug!("{:?}", msg);
            debug!("{:?}", msg.get_name_servers()[3]);
            debug!("{:?}", msg.to_bytes().unwrap().len());
            let mut nsec_bytes = Vec::<u8>::new();
            {
                let mut encoder = BinEncoder::new(&mut nsec_bytes);
                encoder.set_canonical_names(true);
                msg.get_name_servers()[3].emit(&mut encoder).unwrap();
            }
            debug!("{}", nsec_bytes.to_hex());
            let mut validator = DnssecValidator::new(resolver.clone());
            assert!(validator.is_valid(&msg));
        }).unwrap();
    }
}
