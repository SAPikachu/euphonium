use std::sync::Arc;
use std::collections::HashSet;
use std::time::{UNIX_EPOCH, Duration};

use trust_dns::op::{Message, Query, Edns};
use trust_dns::rr::{DNSClass, RecordType, Record, RData, Name};
use trust_dns::rr::rdata::{SIG, DNSKEY, NSEC3};
use trust_dns::rr::dnssec::{TrustAnchor, Verifier};
use trust_dns::serialize::binary::{BinEncoder, BinSerializable};
use itertools::Itertools;
use data_encoding::base32hex;

use resolver::RcResolver;
use utils::{Result};
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
    fn prepare_msg(&mut self, msg: &mut Message, edns: &mut Edns);
}
pub struct DummyValidator;
impl ResponseValidator for DummyValidator {
    fn is_valid(&mut self, _: &Message) -> bool {
        true
    }
    fn prepare_msg(&mut self, _: &mut Message, _: &mut Edns) { }
}
#[cfg(test)]
struct DummyValidatorWithDnssec;
#[cfg(test)]
impl ResponseValidator for DummyValidatorWithDnssec {
    fn is_valid(&mut self, _: &Message) -> bool {
        true
    }
    fn prepare_msg(&mut self, msg: &mut Message, edns: &mut Edns) {
        edns.set_dnssec_ok(true);
        msg.set_checking_disabled(true);
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
#[derive(Eq, PartialEq, Debug)]
enum NsecMatchType {
    Owned,
    Covered,
    All,
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
        let inception = sig.sig_inception() as u64;
        if cur_time < inception {
            cur_time += 0x1_0000_0000;
        }
        let expiration = {
            let t = sig.sig_expiration() as u64;
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
        q.set_name(name.clone());
        q.set_query_type(query_type);
        q.set_query_class(class);
        self.resolver.resolve_sub(q)
    }
    fn verify_ds(&self, dnskey: &Record) -> Result<bool> {
        let (public_key, algorithm) = if let RData::DNSKEY(ref rdata) = *dnskey.rdata() {
            (rdata.public_key(), rdata.algorithm())
        } else {
            panic!("Invalid record type")
        };
        if TRUST_ANCHOR.contains(public_key) {
            return Ok(true);
        }
        let name = dnskey.name();
        if name.is_root() {
            // Avoid infinite loop
            return Ok(false);
        }
        let ds_resp = try!(self.subquery(
            dnskey.name(),
            RecordType::DS,
            dnskey.dns_class(),
        ));
        let mut buf = Vec::<u8>::new();
        {
            let mut encoder = BinEncoder::new(&mut buf);
            encoder.set_canonical_names(true);
            try!(dnskey.name().emit(&mut encoder));
            try!(dnskey.rdata().emit(&mut encoder));
        }
        Ok(ds_resp.answers().iter().any(|x| match *x.rdata() {
            RData::DS(ref ds) if *ds.algorithm() == algorithm => {
                let hash = ds.digest_type().hash(&buf);
                match hash {
                    Ok(h) => *h == *ds.digest(),
                    Err(e) => {
                        warn!("Failed to hash DS: {}", e);
                        false
                    }
                }
            },
            _ => false,
        }))
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
        .map(|rec| if let RData::DNSKEY(ref dnskey) = *rec.rdata() {
            dnskey.clone()
        } else {
            panic!("Invalid record type")
        }).collect_vec()
    }
    fn query_dnskey(&self, signer_name: &Name, rr_class: DNSClass) -> Result<Vec<DNSKEY>> {
        let mut q = Query::new();
        q.set_name(signer_name.clone())
        .set_query_class(rr_class)
        .set_query_type(RecordType::DNSKEY);
        let resp = try!(self.resolver.resolve_sub(q));
        Ok(resp.answers().iter().filter_map(|rec| match *rec.rdata() {
            RData::DNSKEY(ref dnskey) => Some(dnskey.clone()),
            _ => None,
        }).collect_vec())
    }
    fn verify_rrsig<'a, 'b, 'c>(&'a self, rrset: &'b [Record], rrsigs: &'c [SIG]) -> Result<Option<&'c SIG>> {
        assert!(!rrset.is_empty());
        let rr_name = rrset[0].name();
        let rr_class = rrset[0].dns_class();
        let rr_type = rrset[0].rr_type();
        if rrsigs.is_empty() {
            debug!("No RRSIG for {} {:?} {:?}", rr_name, rr_class, rr_type);
            return Ok(None);
        }
        debug_assert!(rrset.iter().all(|x| x.rr_type() == rr_type));
        debug_assert!(rrset.iter().all(|x| x.name() == rr_name));
        debug_assert!(rrsigs.iter().all(|x| x.type_covered() == rr_type));
        for sig in rrsigs {
            if !Self::verify_sig_time(sig) {
                debug!("Not in validity time ({} -> {}).",
                       sig.sig_inception(), sig.sig_expiration());
                continue;
            }
            let signer_name = sig.signer_name();
            // The number of labels in the RRset owner name MUST be greater than
            // or equal to the value in the RRSIG RR's Labels field.
            if rr_name.num_labels() < sig.num_labels() {
                debug!("Number of labels: name = {} ({}), sig = {}",
                       rr_name.num_labels(), rr_name, sig.num_labels());
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
                if key.algorithm() != sig.algorithm() {
                    continue;
                }
                let key_tag = Self::calculate_dnskey_tag(&key);
                if key_tag != sig.key_tag() {
                    continue;
                }
                match key.verify_rrsig(rr_name, rr_class, sig, rrset) {
                    Ok(_) => {
                        trace!("Verified {} {:?} with {:?} (signer: {})",
                               rr_name, rr_type, key.algorithm(), signer_name);
                        return Ok(Some(sig));
                    },
                    Err(e) => {
                        debug!("{:?}", key);
                        debug!("Failed to verify {} {:?} ({}) with ({:?}, {}), \
                                signer: {}, {}",
                               rr_name, rr_type, rrset.len(),
                               key.algorithm(), key_tag,
                               signer_name, e);
                    }
                };
            }
        }
        debug!("No valid RRSIG for {} {:?} {:?}", rr_name, rr_class, rr_type);
        Ok(None)
    }
    // Largely stolen from trust-dns
    fn verify_rrsigs(&self, msg: &Message) -> Result<ValidationResult> {
        debug_assert_eq!(msg.queries().len(), 1);
        let q = &msg.queries()[0];
        let query_name = q.name();
        let query_type = q.query_type();
        let rrset = msg.answers().iter().chain(msg.name_servers()).collect_vec();
        let rrsigs = rrset.iter()
        .filter(|rr| rr.rr_type() == RecordType::RRSIG)
        .collect_vec();

        if rrsigs.is_empty() {
            let mut name = query_name.clone();
            if query_type == RecordType::DS && !name.is_root() {
                name = name.base_name();
            }
            let class = q.query_class();
            while !name.is_root() {
                let ds_resp = try!(self.subquery(&name, RecordType::DS, class));
                let have_ds = ds_resp.answers().iter().any(
                    |rec| *rec.name() == name && rec.rr_type() == RecordType::DS
                );
                if have_ds {
                    // Secure zone, but we got no RRSIG
                    return Ok(ValidationResult::Bogus);
                }
                let have_nsec = ds_resp.name_servers().iter().chain(ds_resp.answers()).any(
                    |rec| match *rec.rdata() {
                        RData::NSEC(ref nsec) => *rec.name() == name && !nsec.type_bit_maps().contains(&RecordType::DS) && !nsec.type_bit_maps().contains(&RecordType::SOA),
                        _ => false,
                    }
                ) || Self::verify_nsec3(&ds_resp.queries()[0], &ds_resp.name_servers().iter().collect_vec()) == ValidationResult::Authenticated;
                if have_nsec {
                    // Insecure zone
                    return Ok(ValidationResult::NonAuthenticated);
                }
                name = name.base_name();
            }
            return Ok(ValidationResult::Bogus);
        }
        // Group the record sets by name and type
        let mut rrset_types: HashSet<(Name, RecordType)> = HashSet::new();
        rrset.iter()
        .filter(|rr| rr.rr_type() != RecordType::RRSIG)
        .map(|rr| (rr.name().clone(), rr.rr_type()))
        .foreach(|rr| { rrset_types.insert(rr); });

        let mut wildcard_num_labels = Option::<u8>::default();
        for (name, rr_type) in rrset_types {
            let rrset_type = rrset.iter()
            .filter(|rr| rr.rr_type() == rr_type && *rr.name() == name)
            .map(|rr| (*rr).clone())
            .collect_vec();
            let rrsig = rrsigs.iter()
            .filter(|rr| *rr.name() == name)
            .filter_map(|rr| if let RData::SIG(ref sig) = *rr.rdata() {
                if sig.type_covered() == rr_type {
                    Some(sig.clone())
                } else {
                    None
                }
            } else {
                panic!("Unexpected RData: {:?}", rr)
            })
            .collect_vec();
            if rr_type == RecordType::NS && rrsig.is_empty() && msg.answers().is_empty() {
                // NS records are not signed in referral
                continue;
            }
            if let Some(sig) = self.verify_rrsig(&rrset_type, &rrsig)? {
                if name == *query_name &&
                    [query_type, RecordType::CNAME].contains(&rr_type) &&
                    sig.num_labels() < query_name.num_labels()
                {
                    wildcard_num_labels = Some(sig.num_labels());
                }
            } else {
                return Ok(ValidationResult::Bogus);
            }
        }
        let have_answer = msg.answers().iter().any(|rec| {
            (rec.rr_type() == query_type ||
             rec.rr_type() == RecordType::CNAME) &&
            rec.name() == query_name
        });
        if have_answer {
            if wildcard_num_labels.is_some() && Self::find_matching_nsec(q, &rrset).is_none() {
                let next_closest = query_name.trim_to(wildcard_num_labels.unwrap() as usize + 1);
                if next_closest.is_root() {
                    return Ok(ValidationResult::Bogus);
                }
                let mut nsec3_query = q.clone();
                nsec3_query.set_name(next_closest);
                return if let Ok(Some(_)) = Self::find_matching_nsec3(&nsec3_query, &rrset, NsecMatchType::Covered) {
                    Ok(ValidationResult::Authenticated)
                } else {
                    Ok(ValidationResult::Bogus)
                };
            }
            return Ok(ValidationResult::Authenticated);
        }
        let is_secure_delegation = msg.name_servers().iter().any(|rec| {
            rec.rr_type() == RecordType::DS && rec.name().zone_of(query_name)
        });
        if is_secure_delegation {
            return Ok(ValidationResult::Authenticated);
        }
        if Self::verify_nsec(q, &rrset) == ValidationResult::Authenticated {
            return Ok(ValidationResult::Authenticated);
        };
        Ok(Self::verify_nsec3(q, &rrset))
    }
    fn verify_nsec(q: &Query, rrset: &[&Record]) -> ValidationResult {
        let nsec_rec = match Self::find_matching_nsec(q, rrset) {
            Some(r) => r,
            None => return ValidationResult::Bogus,
        };
        if q.name() == nsec_rec.name() {
            return ValidationResult::Authenticated;
        }
        let nsec_data = if let RData::NSEC(ref data) = *nsec_rec.rdata() {
            data
        } else {
            panic!("We should only get an NSEC record here");
        };
        // Prove no wildcard exists
        let zone = {
            let mut zone = q.name().base_name();
            let name1 = nsec_rec.name();
            let name2 = nsec_data.next_domain_name();
            loop {
                let should_break = (zone == *name1 || zone.zone_of(name1)) &&
                                   (zone == *name2 || zone.zone_of(name2));
                if should_break {
                    break;
                }
                assert!(!zone.is_root());
                zone = zone.base_name();
            }
            zone
        };
        let mut cur_base = q.name().base_name();
        loop {
            let mut wildcard_query = q.clone();
            let wildcard_name = cur_base.prepend_label(Arc::new("*".into()));
            wildcard_query.set_name(wildcard_name);
            if Self::find_matching_nsec(&wildcard_query, rrset).is_some() {
                return ValidationResult::Authenticated;
            };
            if cur_base == zone {
                break;
            }
            cur_base = cur_base.base_name();
        }
        ValidationResult::Bogus
    }
    #[cfg_attr(feature = "cargo-clippy", allow(collapsible_if))]
    fn find_matching_nsec<'a, 'b>(q: &'a Query, rrset: &'b[&'b Record]) -> Option<&'b Record> {
        let qname = q.name();
        debug!("find_matching_nsec, {}, {:?}", qname, q.query_type());
        rrset.iter().filter_map(|r| {
            let nsec = if let RData::NSEC(ref data) = *r.rdata() {
                data
            } else {
                return None;
            };
            if r.dns_class() != q.query_class() {
                return None;
            }
            if r.name() == qname {
                return if !nsec.type_bit_maps().contains(&q.query_type()) && !nsec.type_bit_maps().contains(&RecordType::CNAME) {
                    Some(r)
                } else {
                    None
                };
            }
            if r.name() == nsec.next_domain_name() {
                warn!("Invalid NSEC record (name == next_name): {:?}", r);
                return None;
            }
            if r.name() < nsec.next_domain_name() {
                if qname > r.name() && qname < nsec.next_domain_name() {
                    Some(r)
                } else {
                    None
                }
            } else {
                if qname < r.name() && qname > nsec.next_domain_name() {
                    Some(r)
                } else {
                    None
                }
            }
        }).map(|r| *r).next()
    }
    fn hash_nsec3(name: &Name, nsec3: &NSEC3) -> Result<String> {
        let hash = nsec3.hash_algorithm().hash(nsec3.salt(), &name.to_lowercase(), nsec3.iterations())?;
        Ok(base32hex::encode(&hash))
    }
    #[cfg_attr(feature = "cargo-clippy", allow(collapsible_if))]
    fn verify_nsec3(q: &Query, rrset: &[&Record]) -> ValidationResult {
        if let Ok(Some(_)) = Self::find_matching_nsec3(q, rrset, NsecMatchType::Owned) {
            return ValidationResult::Authenticated;
        };
        let mut cur_q = q.clone();
        loop {
            let removed_part = cur_q.name()[0].clone();
            let base_name = cur_q.name().base_name();
            cur_q.set_name(base_name.clone());
            cur_q.set_query_type(RecordType::OPT); // qtype is not relevant here, set to an impossible type to ensure skipping qtype check
            // Closest encloser
            match Self::find_matching_nsec3(&cur_q, rrset, NsecMatchType::Owned) {
                Ok(None) | Err(_) => {
                    if cur_q.name().is_root() {
                        return ValidationResult::Bogus;
                    }
                    continue;
                },
                Ok(Some(_)) => {
                    if q.query_type() == RecordType::DS {
                        // Already validated in find_matching_nsec3
                        return ValidationResult::Authenticated;
                    }
                },
            };
            // Next-closest encloser
            cur_q.set_name(base_name.prepend_label(Arc::new(removed_part)));
            cur_q.set_query_type(q.query_type());
            let is_opt_out;
            match Self::find_matching_nsec3(&cur_q, rrset, NsecMatchType::Covered) {
                Ok(None) | Err(_) => return ValidationResult::Bogus,
                Ok(Some(rec)) => {
                    match *rec.rdata() {
                        RData::NSEC3(ref nsec) => {
                            is_opt_out = nsec.opt_out();
                            if q.query_type() == RecordType::DS {
                                if !is_opt_out {
                                    return ValidationResult::Bogus;
                                }
                            }
                        },
                        _ => panic!("Shouldn't reach here"),
                    };
                },
            };
            // Wildcard
            if q.query_type() != RecordType::DS && q.name()[0] != "*" && !is_opt_out {
                cur_q.set_name(base_name.prepend_label(Arc::new("*".into())));
                if Self::find_matching_nsec3(&cur_q, rrset, NsecMatchType::All).unwrap_or_default().is_none() {
                    return ValidationResult::Bogus;
                }
            }
            return ValidationResult::Authenticated;
        }
    }
    #[cfg_attr(feature = "cargo-clippy", allow(collapsible_if))]
    fn find_matching_nsec3<'a, 'b>(q: &'a Query, rrset: &'b[&'b Record], match_type: NsecMatchType) -> Result<Option<&'b Record>> {
        let qname = q.name();
        debug!("find_matching_nsec3, {}, {:?}, {:?}", qname, q.query_type(), match_type);
        let mut hashed_qname_cache = Option::<Result<String>>::default();
        let (find_owned, find_covered) = match match_type {
            NsecMatchType::Owned => (true, false),
            NsecMatchType::Covered => (false, true),
            NsecMatchType::All => (true, true),
        };
        let ret = rrset.iter().filter_map(|r| {
            let nsec = if let RData::NSEC3(ref data) = *r.rdata() {
                data
            } else {
                return None;
            };
            if r.dns_class() != q.query_class() {
                return None;
            }
            let base_name = r.name().base_name();
            if !base_name.zone_of(qname) {
                return None;
            }
            if hashed_qname_cache.is_none() {
                hashed_qname_cache = Some(Self::hash_nsec3(qname, nsec));
            }
            let hashed_qname = match *hashed_qname_cache.as_ref().unwrap() {
                Ok(ref n) => n,
                Err(_) => return None,
            };
            trace!("{} = {}", qname, hashed_qname);
            // base32hex always return uppercased string
            let record_name_hash = r.name()[0].to_uppercase();
            trace!("Record name: {}", record_name_hash);
            debug_assert_eq!(hashed_qname.len(), record_name_hash.len());
            if *hashed_qname == record_name_hash {
                if !find_owned {
                    return None;
                }
                if nsec.type_bit_maps().contains(&q.query_type()) {
                    return None;
                }
                if nsec.type_bit_maps().contains(&RecordType::CNAME) {
                    return None;
                }
                if q.query_type() == RecordType::DS {
                    if !nsec.type_bit_maps().contains(&RecordType::NS) {
                        return None;
                    }
                    if nsec.type_bit_maps().contains(&RecordType::SOA) {
                        return None;
                    }
                }
                return Some(r);
            }
            if !find_covered {
                return None;
            }
            let next_name_hash = base32hex::encode(nsec.next_hashed_owner_name());
            trace!("Next name: {}", next_name_hash);
            debug_assert_eq!(hashed_qname.len(), next_name_hash.len());
            if record_name_hash == next_name_hash {
                warn!("Invalid NSEC3 record (name == next_name): {:?}", r);
                return None;
            }
            if record_name_hash < next_name_hash {
                if *hashed_qname > record_name_hash && *hashed_qname < next_name_hash {
                    Some(r)
                } else {
                    None
                }
            } else {
                if *hashed_qname < record_name_hash && *hashed_qname > next_name_hash {
                    Some(r)
                } else {
                    None
                }
            }
        }).map(|r| *r).next();
        if let Some(Err(e)) = hashed_qname_cache {
            debug_assert!(false);
            return Err(e);
        }
        Ok(ret)
    }
}
impl<T: SubqueryResolver> ResponseValidator for DnssecValidator<T> {
    fn prepare_msg(&mut self, msg: &mut Message, edns: &mut Edns) {
        edns.set_dnssec_ok(true);
        msg.set_checking_disabled(true);
        msg.set_recursion_desired(false);
    }
    fn is_valid(&mut self, msg: &Message) -> bool {
        self.verify_rrsigs(msg).unwrap_or(ValidationResult::Bogus) != ValidationResult::Bogus
    }
}

#[cfg(test)]
mod tests {
    extern crate env_logger;
    use std::net::IpAddr;
    use std::time::Duration;
    use trust_dns::op::*;
    use trust_dns::rr::*;
    use trust_dns::serialize::binary::*;
    use super::*;
    use ::query::query_with_validator;
    use ::config::*;
    use ::resolver::*;
    use ::recursive::*;
    use ::utils::MessageExt;
    use ::mioco_config_start;

    fn test_query_with_server(domain: &str, qtype: RecordType, server: IpAddr) -> Message {
        let mut q = Query::new();
        q.set_name(Name::parse(domain, Some(&Name::root())).unwrap())
        .set_query_class(DNSClass::IN)
        .set_query_type(qtype);
        query_with_validator(q, server, Duration::from_secs(5), &mut DummyValidatorWithDnssec).unwrap()
    }
    fn test_query(domain: &str, qtype: RecordType) -> Message {
        test_query_with_server(domain, qtype, "8.8.8.8".parse().unwrap())
    }

    fn new_resolver() -> RcResolver {
        let mut config = Config::default();
        config.query.enable_dnssec = true;
        RcResolver::new(config)
    }
    fn test_valid_query_nodata(domain: &'static str) {
        test_valid_query_core(domain, RecordType::NULL, |msg| {
            assert!(msg.answers().iter().chain(msg.name_servers()).any(|r| r.rr_type() != RecordType::RRSIG));
            assert!(msg.answers().len() == 0);
        });
    }
    fn test_valid_query_insecure(domain: &'static str) {
        test_valid_query_core(domain, RecordType::A, |msg| assert!(msg.answers().iter().chain(msg.name_servers()).all(|r| r.rr_type() != RecordType::RRSIG)));
    }
    fn test_valid_query(domain: &'static str) {
        test_valid_query_core(domain, RecordType::A, |msg| assert!(msg.answers().iter().chain(msg.name_servers()).any(|r| r.rr_type() == RecordType::RRSIG)));
    }
    fn test_valid_query_nsec3(domain: &'static str) {
        test_valid_query_core(domain, RecordType::A, |msg| {
            assert!(msg.answers().iter().chain(msg.name_servers()).any(|r| r.rr_type() == RecordType::RRSIG));
            assert!(msg.name_servers().iter().any(|r| r.rr_type() == RecordType::NSEC3));
        });
    }
    fn test_valid_query_nsec(domain: &'static str) {
        test_valid_query_core(domain, RecordType::A, |msg| {
            assert!(msg.answers().iter().chain(msg.name_servers()).any(|r| r.rr_type() == RecordType::RRSIG));
            assert!(msg.name_servers().iter().any(|r| r.rr_type() == RecordType::NSEC));
        });
    }
    fn test_valid_query_core<T: FnOnce(&Message) + Send + 'static>(domain: &'static str, qtype: RecordType, extra_check: T) {
        env_logger::init().is_ok();
        mioco_config_start(move || {
            let resolver = new_resolver();
            let mut validator = DnssecValidator::new(resolver.clone());
            let msg = test_query(domain, qtype);
            extra_check(&msg);
            assert!(validator.is_valid(&msg));
            let mut query = Query::new();
            query.set_name(Name::parse(domain, Some(&Name::root())).unwrap());
            query.set_query_type(qtype);
            resolver.resolve_recursive(query).unwrap();
        }).unwrap();
    }
    #[test]
    fn test_dnssec_valid() {
        test_valid_query("sigok.verteiltesysteme.net");
        env_logger::init().is_ok();
        mioco_config_start(move || {
            let resolver = new_resolver();
            let mut validator = DnssecValidator::new(resolver.clone());
            let msg = test_query("sigok.verteiltesysteme.net", RecordType::A);
            assert!(msg.answers().iter().any(|r| r.rr_type() == RecordType::RRSIG));
            assert!(validator.is_valid(&msg));
        }).unwrap();
    }
    #[test]
    fn test_dnssec_valid_wildcard() {
        test_valid_query("a.b.c.d.wildcardtest.sapikachu.com");
        test_valid_query("a.a.a.wildcardtest2.sapikachu.com");
        test_valid_query("a.a.a.a.wildcardtest2.sapikachu.com");
        test_valid_query("c.c.c.c.wildcardtest2.sapikachu.com");
        test_valid_query("c.c.c.wildcardtest2.sapikachu.com");
        test_valid_query("test.c.c.wildcardtest2.sapikachu.com");
        test_valid_query("test.c.c.c.wildcardtest2.sapikachu.com");
        test_valid_query("b.wildcardtest2.sapikachu.com");
    }
    #[test]
    fn test_dnssec_valid_wildcard_nsec() {
        test_valid_query_nsec("a.b.c.d.wildcardtestinvalid.sapikachu.com");
    }
    #[test]
    fn test_dnssec_valid_wildcard_nsec3() {
        test_valid_query_nsec3("x.wilda.0skar.cz");
        test_valid_query_nsec3("a.b.c.x.wilda.0skar.cz");
    }
    #[test]
    fn test_dnssec_valid_cname() {
        env_logger::init().is_ok();
        mioco_config_start(move || {
            let resolver = new_resolver();
            let mut validator = DnssecValidator::new(resolver.clone());
            let msg = test_query("dns1.registrar-servers.com", RecordType::A);
            let ns = msg.answers().iter().filter_map(|r| match *r.rdata() {
                RData::A(ref addr) => Some(addr.clone()),
                _ => None,
            }).next().unwrap();
            let msg = test_query_with_server("sentry.sapikachu.net", RecordType::A, ns.into());
            assert!(msg.answers().iter().any(|r| r.rr_type() == RecordType::RRSIG));
            assert!(validator.is_valid(&msg));
        }).unwrap();
    }
    #[test]
    fn test_dnssec_valid_rollernet() {
        test_valid_query_insecure("ns1.rollernet.us");
    }
    #[test]
    fn test_dnssec_valid_rollernet3() {
        test_valid_query_insecure("nS3-i.rOllErnet.Us");
    }
    #[test]
    fn test_dnssec_insecure_delegation_nsec3_opt_out() {
        test_valid_query_insecure("www.microsoft.com");
        test_valid_query_insecure("www.google.com");
    }
    #[test]
    fn test_dnssec_insecure_delegation_nsec3_no_opt_out() {
        test_valid_query_insecure("www.google.cz");
    }
    #[test]
    fn test_dnssec_insecure_delegation_nsec() {
        test_valid_query_insecure("www.google.us");
    }
    #[test]
    fn test_dnssec_nsec3() {
        test_valid_query_nsec3("nonexistenttestxxxxxx.gov");
        test_valid_query_nsec3("nonexistentxxxxxx.vpsie.com");
        test_valid_query_nsec3("a.b.c.d.nonexistentxxxxxx.vpsie.com");
    }
    #[test]
    fn test_dnssec_valid_nsec() {
        test_valid_query_nsec("nsec.sapikachu.com");
    }
    #[test]
    fn test_dnssec_valid_nodata() {
        test_valid_query_nodata("sapikachu.com");
        test_valid_query_nodata("my.vpsie.com");
    }
    #[test]
    fn test_dnssec_valid_nodata_wildcard_nsec3() {
        test_valid_query_nodata("x.wilda.0skar.cz");
        test_valid_query_nodata("a.b.c.x.wilda.0skar.cz");
    }
    #[test]
    fn test_dnssec_valid_nodata_wildcard() {
        test_valid_query_nodata("a.b.c.d.wildcardtest.sapikachu.com");
    }
    #[test]
    fn test_dnssec_valid_cloudflare_nsec() {
        test_valid_query_nsec("nsec.cloudflare.com");
    }
    #[test]
    fn test_dnssec_valid_cloudflare() {
        test_valid_query("blog.cloudflare.com");
    }
    #[test]
    fn test_dnssec_invalid() {
        env_logger::init().is_ok();
        mioco_config_start(move || {
            let resolver = new_resolver();
            let msg = test_query("sigfail.verteiltesysteme.net", RecordType::A);
            assert!(msg.answers().iter().any(|r| r.rr_type() == RecordType::RRSIG));
            let mut validator = DnssecValidator::new(resolver.clone());
            assert!(!validator.is_valid(&msg));
        }).unwrap();
    }
    #[test]
    fn test_dnssec_integrated() {
        env_logger::init().is_ok();
        mioco_config_start(move || {
            let resolver = new_resolver();
            let mut q = Query::new();
            q.set_name(Name::parse("sigok.verteiltesysteme.net.", None).unwrap())
            .set_query_class(DNSClass::IN)
            .set_query_type(RecordType::A);
            RecursiveResolver::resolve(&q, resolver.clone()).unwrap();
            q.set_name(Name::parse("nS3-i.rOllErnet.Us.", None).unwrap());
            RecursiveResolver::resolve(&q, resolver.clone()).unwrap();
            q.set_name(Name::parse("ns1.rollernet.us.", None).unwrap());
            RecursiveResolver::resolve(&q, resolver.clone()).unwrap();
            q.set_name(Name::parse("sentry.sapikachu.net.", None).unwrap());
            RecursiveResolver::resolve(&q, resolver.clone()).unwrap();
            q.set_name(Name::parse("blog.cloudflare.com.", None).unwrap());
            RecursiveResolver::resolve(&q, resolver.clone()).unwrap();
            q.set_name(Name::parse("nsectest.cloudflare.com.", None).unwrap());
            RecursiveResolver::resolve(&q, resolver.clone()).unwrap();
            q.set_name(Name::parse("sigfail.verteiltesysteme.net.", None).unwrap());
            RecursiveResolver::resolve(&q, resolver.clone()).unwrap_err();
        }).unwrap();
    }
    #[allow(dead_code)]
    fn test_dnssec_rollernet() {
        // This test will fail after signature in the data is expired, leaving here for
        // reference only
        env_logger::init().is_ok();
        mioco_config_start(move || {
            let resolver = new_resolver();
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
            debug!("{:?}", msg.name_servers()[3]);
            debug!("{:?}", msg.to_bytes().unwrap().len());
            let mut nsec_bytes = Vec::<u8>::new();
            {
                let mut encoder = BinEncoder::new(&mut nsec_bytes);
                encoder.set_canonical_names(true);
                msg.name_servers()[3].emit(&mut encoder).unwrap();
            }
            debug!("{}", nsec_bytes.to_hex());
            let mut validator = DnssecValidator::new(resolver.clone());
            assert!(validator.is_valid(&msg));
        }).unwrap();
    }
}
