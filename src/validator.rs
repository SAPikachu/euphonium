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
        let mut q = Query::new();
        q.name(dnskey.get_name().clone());
        q.query_type(RecordType::DS);
        q.query_class(dnskey.get_dns_class());
        let ds_resp = try!(self.resolver.resolve_sub(q));
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
        let rrsigs = msg.get_answers().iter()
        .chain(msg.get_name_servers())
        .filter(|rr| rr.get_rr_type() == RecordType::RRSIG)
        .collect_vec();

        if rrsigs.is_empty() {
            // TODO: Check whether this zone is really not signed
            debug!("No Sig");
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

        // TODO: Verify NSEC/NSEC3
        Ok(ValidationResult::Authenticated)
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
    use super::*;
    use ::query::query;
    use ::resolver::*;
    use ::mioco_config_start;

    fn test_query(domain: &str) -> Message {
        let mut q = Query::new();
        q.name(Name::parse(domain, Some(&Name::root())).unwrap())
        .query_class(DNSClass::IN)
        .query_type(RecordType::A);
        let msg = query(q, "8.8.8.8".parse().unwrap(), Duration::from_secs(5)).unwrap();
        assert!(msg.get_answers().iter().any(|r| r.get_rr_type() == RecordType::RRSIG));
        msg
    }

    #[test]
    fn test_dnssec_valid() {
        env_logger::init().is_ok();
        mioco_config_start(move || {
            let resolver = RcResolver::default();
            let msg = test_query("sigok.verteiltesysteme.net");
            let mut validator = DnssecValidator::new(resolver.clone());
            assert!(validator.is_valid(&msg));
        }).unwrap();
    }
    #[test]
    fn test_dnssec_invalid() {
        env_logger::init().is_ok();
        mioco_config_start(move || {
            let resolver = RcResolver::default();
            let msg = test_query("sigfail.verteiltesysteme.net");
            let mut validator = DnssecValidator::new(resolver.clone());
            assert!(!validator.is_valid(&msg));
        }).unwrap();
    }
}
