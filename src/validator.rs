#![cfg_attr(debug_assertions, allow(unused_imports, dead_code))]

use std::collections::HashSet;

use trust_dns::op::{Message, MessageType, ResponseCode, Query, OpCode, Edns};
use trust_dns::rr::{DNSClass, RecordType, Record, RData, Name};
use trust_dns::rr::rdata::sig::SIG;
use trust_dns::rr::dnssec::Signer;
use openssl::crypto::pkey::Role;
use itertools::Itertools;

use resolver::RcResolver;
use utils::Result;
use recursive::RecursiveResolver;

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
pub struct DnssecValidator {
    resolver: RcResolver,
}
impl DnssecValidator {
    pub fn new(resolver: RcResolver) -> Self {
        DnssecValidator {
            resolver: resolver,
        }
    }
    fn verify_rrsig(&self, rrset: &[Record], rrsigs: &[SIG]) -> Result<ValidationResult> {
        assert!(!rrset.is_empty());
        if rrsigs.is_empty() {
            return Ok(ValidationResult::Bogus);
        }
        let rr_type = rrsigs[0].get_type_covered();
        let rr_name = rrset[0].get_name();
        let rr_class = rrset[0].get_dns_class();
        debug_assert!(rrset.iter().all(|x| x.get_rr_type() == rr_type));
        debug_assert!(rrset.iter().all(|x| x.get_name() == rr_name));
        debug_assert!(rrsigs.iter().all(|x| x.get_type_covered() == rr_type));
        for sig in rrsigs {
            let signer_name = sig.get_signer_name();
            let dnskeys = if rr_type == RecordType::DNSKEY && signer_name == rr_name {
                // TODO: Self-signed, verify DS
                rrset.iter().map(|rec| if let RData::DNSKEY(ref dnskey) = *rec.get_rdata() {
                    dnskey.clone()
                } else {
                    panic!("Invalid record type")
                }).collect_vec()
            } else {
                let mut q = Query::new();
                q.name(signer_name.clone())
                .query_class(rr_class)
                .query_type(RecordType::DNSKEY);
                let resp = try!(RecursiveResolver::resolve(&q, self.resolver.clone()));
                resp.get_answers().iter().filter_map(|rec| match *rec.get_rdata() {
                    RData::DNSKEY(ref dnskey) => Some(dnskey.clone()),
                    _ => None,
                }).collect_vec()
            };
            for key in dnskeys {
                if key.is_revoke() {
                    debug!("DNSKEY is revoked: {:?}", key);
                    continue;
                }
                if !key.is_zone_key() {
                    continue;
                }
                if *key.get_algorithm() != sig.get_algorithm() {
                    continue;
                }
                let pkey = key.get_algorithm().public_key_from_vec(key.get_public_key());
                let pkey = match pkey {
                    Ok(k) => k,
                    Err(e) => {
                        warn!("Failed to get public key from DNSKEY: {:?}", e);
                        continue
                    },
                };
                if !pkey.can(Role::Verify) {
                    debug!("PKey can't be used to verify: {:?}", key);
                }
                let signer = Signer::new_verifier(
                    *key.get_algorithm(), pkey, signer_name.clone(),
                );
                let rrset_hash: Vec<u8> = signer.hash_rrset(
                    rr_name, rr_class,
                    sig.get_num_labels(), sig.get_type_covered(), sig.get_algorithm(),
                    sig.get_original_ttl(), sig.get_sig_expiration(), sig.get_sig_inception(),
                    sig.get_key_tag(), signer_name, rrset,
                );
                if signer.verify(&rrset_hash, sig.get_sig()) {
                    return Ok(ValidationResult::Authenticated);
                } else {
                    debug!("Failed to verify {} {:?} with {:?}", rr_name, rr_type, key);
                }
            }
        }
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
            if try!(self.verify_rrsig(&rrset, &rrsig)) != ValidationResult::Authenticated {
                return Ok(ValidationResult::Bogus);
            }
        }

        // TODO: Verify NSEC/NSEC3
        Ok(ValidationResult::Authenticated)
    }
}
impl ResponseValidator for DnssecValidator {
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