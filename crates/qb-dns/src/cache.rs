//! The cache of upstream answers: how long an answer may be kept, and whether a stored one is
//! fresh, stale but still usable, or gone.
//!
//! Every time here is in seconds on the monotonic clock, so a step of the wall clock moves
//! nothing. All arithmetic on times and lifetimes is saturating or checked: no time, lifetime or
//! stored value makes a call panic or wrap.

use hickory_proto::op::Message;
use hickory_proto::rr::RData;

use crate::lru::Lru;
use crate::query::ResponseCode;

/// The most answers kept; storing one more evicts the least recently used.
pub(crate) const CACHE_CAPACITY: usize = 10_000;
/// The least seconds an answer is kept, however low its TTL.
pub(crate) const TTL_FLOOR: u32 = 30;
/// The most seconds an answer with records is kept, however high its TTL.
pub(crate) const TTL_CEILING: u32 = 86_400;
/// The most seconds a "no such name" or "no such record" answer is kept.
pub(crate) const NEGATIVE_TTL_CEILING: u32 = 3_600;
/// How long past its lifetime an answer may still be served as stale: under this many seconds.
pub(crate) const STALE_MAX_SECS: u64 = 3_600;
/// The TTL every record of a stale answer is sent with (RFC 8767 section 4).
pub(crate) const STALE_TTL: u32 = 30;
/// The least seconds between two refresh requests for one stale entry.
pub(crate) const REFRESH_RETRY_SECS: u64 = 10;
/// The longest answer stored, in bytes.
pub(crate) const MAX_ENTRY_BYTES: usize = 4_096;
/// How many fresh hits an entry needs since it was stored before it is worth a prefetch, the hit
/// that asks included.
pub(crate) const PREFETCH_MIN_HITS: u16 = 3;
/// The least seconds of lifetime left at which a prefetch is asked for.
pub(crate) const PREFETCH_WINDOW_MIN: u32 = 2;
/// The most seconds of lifetime left at which a prefetch is asked for.
pub(crate) const PREFETCH_WINDOW_MAX: u32 = 60;

/// The top bit of a TTL, which makes the whole value count as 0 (RFC 2181 section 8).
const TTL_TOP_BIT: u32 = 0x8000_0000;

/// What an answer is stored under. The cache does not look inside: whoever builds a key decides
/// its content, and two keys are the same entry only if every field is equal.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Key {
    /// The name asked for.
    pub(crate) name: Box<str>,
    /// The record type asked for, as its number.
    pub(crate) qtype: u16,
    /// Whether the query had the DO bit set, since such an answer carries DNSSEC records.
    pub(crate) dnssec_ok: bool,
}

/// A stored answer found by [`Cache::get`].
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Hit<'a> {
    /// Within its lifetime.
    Fresh {
        /// The answer as it was stored.
        body: &'a [u8],
        /// The seconds of lifetime left: at least 1.
        ttl: u32,
        /// Whether the caller should now ask upstream for a new answer before this one expires,
        /// because the entry is popular and near its end. True at most once per stored answer, and
        /// only with prefetch on: see [`Cache::set_prefetch`].
        prefetch: bool,
    },
    /// Past its lifetime by less than [`STALE_MAX_SECS`].
    Stale {
        /// The answer as it was stored.
        body: &'a [u8],
        /// Whether the caller should now ask upstream again. True at most once per
        /// [`REFRESH_RETRY_SECS`] for an entry.
        refresh: bool,
    },
}

/// Whether `upstream` is an answer rather than a failure: not truncated, and NOERROR or NXDOMAIN.
/// Such an answer replaces what is stored for its question, whether or not it can be stored.
pub(crate) fn is_definitive(upstream: &Message) -> bool {
    !upstream.metadata.truncation
        && matches!(
            upstream.metadata.response_code,
            ResponseCode::NoError | ResponseCode::NXDomain
        )
}

/// How many seconds `upstream` may be cached, or `None` if it may not be.
///
/// - Not [`is_definitive`]: not cached.
/// - NOERROR with answers: the lowest answer TTL, held to [`TTL_FLOOR`]..=[`TTL_CEILING`].
/// - NXDOMAIN, or NOERROR with no answer (RFC 2308 section 5): the lower of the TTL and the
///   MINIMUM of the SOA in the authority section, held to
///   [`TTL_FLOOR`]..=[`NEGATIVE_TTL_CEILING`]; not cached without an SOA. The answers of an
///   NXDOMAIN, which are the aliases that led to the missing name, lower it too: they are stored
///   with it and must not outlive their own TTLs.
/// - NOERROR with answers and an SOA in the authority section, which is no data reached through
///   an alias: as for no answer, with the lowest answer TTL one more value to take the lower of.
///   The aliases do not say how long the record asked for stays missing; the SOA does.
///
/// Only the message is read; whether it answers the question asked is the caller's check.
pub(crate) fn lifetime(upstream: &Message) -> Option<u32> {
    if !is_definitive(upstream) {
        return None;
    }
    let lowest_answer = upstream
        .answers
        .iter()
        .map(|record| counted_ttl(record.ttl))
        .min();
    let negative = upstream
        .authorities
        .iter()
        .filter_map(|record| match &record.data {
            RData::SOA(soa) => Some(counted_ttl(record.ttl).min(counted_ttl(soa.minimum))),
            _ => None,
        })
        .min();
    match (upstream.metadata.response_code, lowest_answer, negative) {
        (ResponseCode::NoError, Some(answer), None) => Some(answer.clamp(TTL_FLOOR, TTL_CEILING)),
        (_, answer, Some(negative)) => {
            let lowest = answer.map_or(negative, |answer| answer.min(negative));
            Some(lowest.clamp(TTL_FLOOR, NEGATIVE_TTL_CEILING))
        }
        _ => None,
    }
}

/// The seconds of lifetime left at which an entry of `lifetime` seconds is prefetched: a tenth of
/// the lifetime, held to [`PREFETCH_WINDOW_MIN`]..=[`PREFETCH_WINDOW_MAX`].
fn prefetch_window(lifetime: u32) -> u32 {
    (lifetime / 10).clamp(PREFETCH_WINDOW_MIN, PREFETCH_WINDOW_MAX)
}

/// What a TTL on the wire counts as: 0 if its top bit is set, else itself.
fn counted_ttl(ttl: u32) -> u32 {
    if ttl & TTL_TOP_BIT == 0 { ttl } else { 0 }
}

/// One stored answer.
struct Entry {
    /// The answer, in an allocation of exactly its length.
    body: Box<[u8]>,
    /// When it was stored.
    stored_at: u64,
    /// The seconds from `stored_at` during which it is fresh.
    lifetime: u32,
    /// When a refresh was last asked for, or `None` if never since it was stored.
    refresh_asked_at: Option<u64>,
    /// The fresh hits since it was stored, saturating.
    hits: u16,
    /// Whether a prefetch was asked for since it was stored.
    prefetch_asked: bool,
}

/// Upstream answers by key: at most `capacity` of them, of at most [`MAX_ENTRY_BYTES`] each.
pub(crate) struct Cache {
    entries: Lru<Key, Entry>,
    /// Whether [`Hit::Fresh`] ever asks for a prefetch.
    prefetch: bool,
}

impl Cache {
    /// An empty cache holding at most `capacity` answers; 0 is treated as 1.
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            entries: Lru::new(capacity),
            prefetch: false,
        }
    }

    /// Turns prefetch on or off; it is off until set. On, a fresh hit says so, once per stored
    /// answer, when the entry has had [`PREFETCH_MIN_HITS`] fresh hits since it was stored (this
    /// one included) and its lifetime left is within a tenth of its lifetime, held to
    /// [`PREFETCH_WINDOW_MIN`]..=[`PREFETCH_WINDOW_MAX`] seconds. Off, nothing changes for a hit.
    /// An entry stored again starts over: its hits are counted from 0 and it may be asked for
    /// once more.
    pub(crate) fn set_prefetch(&mut self, on: bool) {
        self.prefetch = on;
    }

    /// Stores `body` under `key` as fresh for `lifetime` seconds from `mono_secs`, in place of
    /// any entry with that key; a full cache evicts its least recently used entry. Returns
    /// whether it was stored: a body over [`MAX_ENTRY_BYTES`] is not, and an entry already there
    /// stays as it was. Whether that entry should go is for the caller to say, with
    /// [`Cache::remove`].
    pub(crate) fn insert(
        &mut self,
        key: Key,
        body: Vec<u8>,
        lifetime: u32,
        mono_secs: u64,
    ) -> bool {
        if body.len() > MAX_ENTRY_BYTES {
            return false;
        }
        let entry = Entry {
            body: body.into_boxed_slice(),
            stored_at: mono_secs,
            lifetime,
            refresh_asked_at: None,
            hits: 0,
            prefetch_asked: false,
        };
        self.entries.insert(key, entry);
        true
    }

    /// Drops the entry stored under `key`, fresh, stale or otherwise; nothing if there is none.
    pub(crate) fn remove(&mut self, key: &Key) {
        self.entries.remove(key);
    }

    /// The answer stored under `key`, as it stands at `mono_secs`: fresh, stale, or `None`. A hit
    /// makes the entry the most recently used, and a fresh one is counted for the prefetch
    /// (see [`Cache::set_prefetch`]); an entry too old to serve even as stale is removed. A time
    /// before the entry was stored counts as the moment it was stored.
    pub(crate) fn get(&mut self, key: &Key, mono_secs: u64) -> Option<Hit<'_>> {
        let entry = self.entries.peek(key)?;
        let age = mono_secs.saturating_sub(entry.stored_at);
        let servable_for = u64::from(entry.lifetime).saturating_add(STALE_MAX_SECS);
        if age >= servable_for {
            self.entries.remove(key);
            return None;
        }

        let prefetch_on = self.prefetch;
        let entry = self.entries.get_mut(key)?;
        // The seconds of lifetime left. `None` when the age does not fit a `u32`, or is over the
        // lifetime: either way the lifetime is over.
        let left = u32::try_from(age)
            .ok()
            .and_then(|age| entry.lifetime.checked_sub(age));
        if let Some(ttl) = left.filter(|&ttl| ttl > 0) {
            entry.hits = entry.hits.saturating_add(1);
            // With the switch off this is one test of a flag.
            let prefetch = prefetch_on
                && !entry.prefetch_asked
                && entry.hits >= PREFETCH_MIN_HITS
                && ttl <= prefetch_window(entry.lifetime);
            entry.prefetch_asked |= prefetch;
            return Some(Hit::Fresh {
                body: &entry.body,
                ttl,
                prefetch,
            });
        }
        let refresh = entry
            .refresh_asked_at
            .is_none_or(|asked_at| mono_secs.saturating_sub(asked_at) >= REFRESH_RETRY_SECS);
        if refresh {
            entry.refresh_asked_at = Some(mono_secs);
        }
        Some(Hit::Stale {
            body: &entry.body,
            refresh,
        })
    }

    /// How many answers are held, stale ones included.
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use hickory_proto::op::OpCode;
    use hickory_proto::rr::rdata::{A, CNAME, NS, SOA};
    use hickory_proto::rr::{Name, Record};

    use super::*;
    use crate::testutil::{R_A, R_NODATA, R_NXDOMAIN, Rng, decode, unhex};

    const B: &[u8] = &[7; 61];

    fn name(ascii: &str) -> Name {
        Name::from_ascii(ascii).unwrap()
    }

    /// A NOERROR response with one `example.com` A record per TTL.
    fn positive(ttls: &[u32]) -> Message {
        let mut message = Message::response(0x1234, OpCode::Query);
        message.add_answers(ttls.iter().map(|&ttl| {
            let address = RData::A(A(Ipv4Addr::new(192, 0, 2, 1)));
            Record::from_rdata(name("example.com."), ttl, address)
        }));
        message
    }

    /// A response with no answer and, when given, one SOA in the authority section with that
    /// TTL and MINIMUM.
    fn negative(rcode: ResponseCode, soa: Option<(u32, u32)>) -> Message {
        let mut message = Message::response(0x1234, OpCode::Query);
        message.metadata.response_code = rcode;
        if let Some((ttl, minimum)) = soa {
            let soa = SOA::new(
                name("ns.example.com."),
                name("hostmaster.example.com."),
                1,
                7200,
                3600,
                1_209_600,
                minimum,
            );
            message.add_authority(Record::from_rdata(
                name("example.com."),
                ttl,
                RData::SOA(soa),
            ));
        }
        message
    }

    fn key(qtype: u16, dnssec_ok: bool) -> Key {
        Key {
            name: "example.com".into(),
            qtype,
            dnssec_ok,
        }
    }

    #[test]
    fn lifetime_of_real_answers() {
        assert_eq!(lifetime(&decode(&unhex(R_A))), Some(215));
        assert_eq!(lifetime(&decode(&unhex(R_NODATA))), Some(1800));
        // 10800, held to the negative ceiling.
        assert_eq!(lifetime(&decode(&unhex(R_NXDOMAIN))), Some(3600));
    }

    #[test]
    fn lifetime_is_the_lowest_answer_ttl_within_the_limits() {
        // The last: a TTL with the top bit set counts as 0.
        for (ttls, want) in [
            (vec![300, 60, 900], 60),
            (vec![5], 30),
            (vec![0], 30),
            (vec![1_000_000], 86_400),
            (vec![0x8000_00d7, 600], 30),
        ] {
            assert_eq!(lifetime(&positive(&ttls)), Some(want), "{ttls:?}");
        }
    }

    #[test]
    fn negative_lifetime_follows_rfc_2308() {
        assert_eq!(
            lifetime(&negative(ResponseCode::NXDomain, Some((900, 60)))),
            Some(60)
        );
        assert_eq!(
            lifetime(&negative(ResponseCode::NXDomain, Some((20, 300)))),
            Some(30)
        );
        assert_eq!(
            lifetime(&negative(ResponseCode::NoError, Some((7200, 7200)))),
            Some(3600)
        );
        assert_eq!(lifetime(&negative(ResponseCode::NXDomain, None)), None);
        assert_eq!(lifetime(&negative(ResponseCode::NoError, None)), None);
    }

    #[test]
    fn an_soa_value_with_the_top_bit_set_counts_as_0() {
        for soa in [(0x8000_0384, 900), (900, 0x8000_0384)] {
            assert_eq!(
                lifetime(&negative(ResponseCode::NXDomain, Some(soa))),
                Some(30),
                "{soa:?}"
            );
        }
    }

    #[test]
    fn the_lowest_of_several_soa_records_counts() {
        let mut message = negative(ResponseCode::NXDomain, Some((900, 900)));
        let second = negative(ResponseCode::NXDomain, Some((300, 600)));
        message.add_authorities(second.authorities);
        assert_eq!(lifetime(&message), Some(300));
    }

    #[test]
    fn only_an_soa_in_the_authority_section_makes_a_negative_answer_cacheable() {
        let soa = negative(ResponseCode::NXDomain, Some((900, 900))).authorities;
        let mut elsewhere = negative(ResponseCode::NXDomain, None);
        elsewhere.add_additionals(soa);
        assert_eq!(lifetime(&elsewhere), None);
        // A referral: name servers in the authority section, no SOA.
        let mut referral = negative(ResponseCode::NoError, None);
        referral.add_authority(Record::from_rdata(
            name("example.com."),
            900,
            RData::NS(NS(name("ns.example.com."))),
        ));
        assert_eq!(lifetime(&referral), None);
    }

    #[test]
    fn an_alias_to_a_missing_name_is_kept_no_longer_than_the_alias() {
        let mut message = negative(ResponseCode::NXDomain, Some((900, 900)));
        message.add_answer(Record::from_rdata(
            name("example.com."),
            120,
            RData::CNAME(CNAME(name("host.invalid."))),
        ));
        assert_eq!(lifetime(&message), Some(120));
        message.answers[0].ttl = 7200;
        assert_eq!(lifetime(&message), Some(900));
        message.answers[0].ttl = 100_000;
        message.authorities[0].ttl = 100_000;
        assert_eq!(lifetime(&message), Some(900));
        message.authorities.clear();
        assert_eq!(lifetime(&message), None);
    }

    // NODATA reached through an alias: the answer holds only the alias, and the SOA says how long
    // the missing records stay missing.
    #[test]
    fn a_noerror_answer_with_an_soa_is_kept_no_longer_than_the_soa() {
        let alias = |ttl| {
            let target = RData::CNAME(CNAME(name("host.example.com.")));
            Record::from_rdata(name("www.example.com."), ttl, target)
        };
        for (alias_ttl, soa, want) in [
            (86_400, (900, 900), 900),
            (86_400, (900, 60), 60),
            (86_400, (60, 900), 60),
            (86_400, (10, 10), 30),
            // Held to the negative ceiling, as an NXDOMAIN is.
            (86_400, (7200, 7200), 3600),
            // The alias is the lower of the two.
            (120, (900, 900), 120),
            (120, (3600, 3600), 120),
            (10, (900, 900), 30),
            (0x8000_0001, (900, 900), 30),
        ] {
            let mut message = negative(ResponseCode::NoError, Some(soa));
            message.add_answer(alias(alias_ttl));
            assert_eq!(lifetime(&message), Some(want), "{alias_ttl} {soa:?}");
        }
        // The same holds for an answer of the type asked for that has an SOA beside it.
        let mut message = positive(&[86_400]);
        message.add_authorities(negative(ResponseCode::NoError, Some((900, 900))).authorities);
        assert_eq!(lifetime(&message), Some(900));
        // An SOA anywhere else does not count, and none leaves the answer's lifetime alone.
        let mut elsewhere = positive(&[86_400]);
        elsewhere.add_additionals(negative(ResponseCode::NoError, Some((900, 900))).authorities);
        assert_eq!(lifetime(&elsewhere), Some(86_400));
    }

    #[test]
    fn failures_and_truncated_answers_are_not_cached() {
        assert_eq!(
            lifetime(&negative(ResponseCode::ServFail, Some((900, 60)))),
            None
        );
        assert_eq!(lifetime(&negative(ResponseCode::Refused, None)), None);
        let mut tc = positive(&[300]);
        tc.metadata.truncation = true;
        assert_eq!(lifetime(&tc), None);
        let mut failed = positive(&[300]);
        failed.metadata.response_code = ResponseCode::ServFail;
        assert_eq!(lifetime(&failed), None);
        let mut tc = negative(ResponseCode::NXDomain, Some((900, 60)));
        tc.metadata.truncation = true;
        assert_eq!(lifetime(&tc), None);
    }

    #[test]
    fn lifetime_of_arbitrary_answers_stays_within_the_limits() {
        let mut rng = Rng::new(8);
        let (mut positive, mut negative, mut uncached) = (0, 0, 0);
        for base in [R_A, R_NODATA, R_NXDOMAIN] {
            let base = unhex(base);
            for _ in 0..20_000 {
                let Ok(message) = Message::from_vec(&rng.mutate(&base)) else {
                    continue;
                };
                let found = message.metadata.response_code == ResponseCode::NoError
                    && !message.answers.is_empty();
                match lifetime(&message) {
                    None => uncached += 1,
                    Some(secs) if found => {
                        assert!((TTL_FLOOR..=TTL_CEILING).contains(&secs), "{secs}");
                        positive += 1;
                    }
                    Some(secs) => {
                        assert!((TTL_FLOOR..=NEGATIVE_TTL_CEILING).contains(&secs), "{secs}");
                        negative += 1;
                    }
                }
            }
        }
        // The run must have reached every kind of result. Few changes make an answer
        // uncacheable, so that count is the lowest: 795 with this seed.
        assert!(
            positive > 1_000 && negative > 1_000 && uncached > 500,
            "{positive} positive, {negative} negative, {uncached} not cached"
        );
    }

    #[test]
    fn fresh_then_stale_then_gone() {
        let (mut c, k) = (Cache::new(10), key(1, false));
        c.insert(k.clone(), B.to_vec(), 215, 1000);
        for (mono, ttl) in [(1000, 215), (1100, 115), (1214, 1)] {
            assert_eq!(
                c.get(&k, mono),
                Some(Hit::Fresh {
                    body: B,
                    ttl,
                    prefetch: false
                })
            );
        }
        for (mono, refresh) in [
            (1215, true),
            (1216, false),
            (1224, false),
            (1225, true),
            (4814, true),
        ] {
            assert_eq!(
                c.get(&k, mono),
                Some(Hit::Stale { body: B, refresh }),
                "{mono}"
            );
        }
        assert_eq!(c.get(&k, 4815), None);
        assert_eq!(c.len(), 0);
        c.insert(k.clone(), B.to_vec(), 215, 5000);
        // Review Focus 4: an earlier time does not underflow.
        assert_eq!(
            c.get(&k, 900),
            Some(Hit::Fresh {
                body: B,
                ttl: 215,
                prefetch: false
            })
        );
    }

    #[test]
    fn storing_again_makes_it_fresh() {
        let (mut c, k) = (Cache::new(10), key(1, false));
        c.insert(k.clone(), vec![1], 60, 0);
        assert_eq!(
            c.get(&k, 60),
            Some(Hit::Stale {
                body: &[1],
                refresh: true
            })
        );
        c.insert(k.clone(), vec![2], 60, 61);
        assert_eq!(
            c.get(&k, 62),
            Some(Hit::Fresh {
                body: &[2],
                ttl: 59,
                prefetch: false
            })
        );
        // The refresh mark was cleared.
        assert_eq!(
            c.get(&k, 121),
            Some(Hit::Stale {
                body: &[2],
                refresh: true
            })
        );
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn keys_split_on_type_and_dnssec_ok() {
        let mut c = Cache::new(10);
        c.insert(key(1, false), vec![1], 60, 0);
        assert!(
            c.get(&key(28, false), 0).is_none()
                && c.get(&key(1, true), 0).is_none()
                && c.get(&key(1, false), 0).is_some()
        );
    }

    #[test]
    fn oversized_bodies_are_not_stored() {
        let mut c = Cache::new(10);
        assert!(!c.insert(key(1, false), vec![0; 4097], 60, 0));
        assert_eq!(c.len(), 0);
        assert!(c.insert(key(1, false), vec![0; 4096], 60, 0));
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn an_oversized_body_leaves_the_stored_entry_as_it_was() {
        let (mut c, k) = (Cache::new(10), key(1, false));
        assert!(c.insert(k.clone(), vec![1], 60, 0));
        assert_eq!(
            c.get(&k, 60),
            Some(Hit::Stale {
                body: &[1],
                refresh: true
            })
        );
        assert!(!c.insert(k.clone(), vec![0; MAX_ENTRY_BYTES + 1], 60, 61));
        // Still the old body, still stale, and its refresh was asked for 2 seconds ago.
        assert_eq!(
            c.get(&k, 62),
            Some(Hit::Stale {
                body: &[1],
                refresh: false
            })
        );
    }

    #[test]
    fn remove_drops_the_entry_of_one_key_only() {
        let mut c = Cache::new(10);
        c.insert(key(1, false), vec![1], 60, 0);
        c.insert(key(28, false), vec![2], 60, 0);
        c.remove(&key(1, false));
        // A key that is not there is not an error.
        c.remove(&key(1, false));
        c.remove(&key(1, true));
        assert!(c.get(&key(1, false), 1).is_none() && c.get(&key(28, false), 1).is_some());
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn capacity_evicts_the_least_recently_used() {
        let mut c = Cache::new(2);
        c.insert(key(1, false), vec![1], 60, 0);
        c.insert(key(2, false), vec![2], 60, 0);
        assert!(c.get(&key(1, false), 1).is_some());
        c.insert(key(3, false), vec![3], 60, 2);
        assert!(
            c.get(&key(2, false), 3).is_none()
                && c.get(&key(1, false), 3).is_some()
                && c.get(&key(3, false), 3).is_some()
        );
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn a_stale_hit_counts_as_a_use() {
        let mut c = Cache::new(2);
        c.insert(key(1, false), vec![1], 60, 0);
        c.insert(key(2, false), vec![2], 60, 0);
        assert!(matches!(c.get(&key(1, false), 60), Some(Hit::Stale { .. })));
        c.insert(key(3, false), vec![3], 60, 61);
        assert!(c.get(&key(2, false), 61).is_none() && c.get(&key(1, false), 61).is_some());
    }

    #[test]
    fn an_expired_entry_makes_room() {
        let mut c = Cache::new(2);
        c.insert(key(1, false), vec![1], 60, 0);
        c.insert(key(2, false), vec![2], 60, 4000);
        assert_eq!(c.get(&key(1, false), 4000), None);
        // With key 1 gone, key 3 fits without evicting key 2.
        c.insert(key(3, false), vec![3], 60, 4000);
        assert!(c.get(&key(2, false), 4000).is_some() && c.get(&key(3, false), 4000).is_some());
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn extreme_times_and_lifetimes_do_not_overflow() {
        let (mut c, k) = (Cache::new(10), key(1, false));
        let stale = |refresh| Some(Hit::Stale { body: B, refresh });
        let fresh = |ttl| {
            Some(Hit::Fresh {
                body: B,
                ttl,
                prefetch: false,
            })
        };

        // The longest lifetime, stored at the last second there is.
        c.insert(k.clone(), B.to_vec(), u32::MAX, u64::MAX);
        assert_eq!(c.get(&k, u64::MAX), fresh(u32::MAX));
        assert_eq!(c.get(&k, 0), fresh(u32::MAX));

        // The longest lifetime, lived to its end and through the stale hour.
        let end = u64::from(u32::MAX);
        c.insert(k.clone(), B.to_vec(), u32::MAX, 0);
        assert_eq!(c.get(&k, end - 1), fresh(1));
        assert_eq!(c.get(&k, end), stale(true));
        assert_eq!(c.get(&k, end + STALE_MAX_SECS - 1), stale(true));
        assert_eq!(c.get(&k, end + STALE_MAX_SECS), None);

        // The same entry, asked for at the last second there is.
        c.insert(k.clone(), B.to_vec(), u32::MAX, 0);
        assert_eq!(c.get(&k, u64::MAX), None);

        // No lifetime at all: stale from the start.
        c.insert(k.clone(), B.to_vec(), 0, 7);
        assert_eq!(c.get(&k, 7), stale(true));
        assert_eq!(c.get(&k, 7 + STALE_MAX_SECS - 1), stale(true));
        assert_eq!(c.get(&k, 7 + STALE_MAX_SECS), None);

        // A refresh asked for near the last second, and a time before the last request.
        c.insert(k.clone(), B.to_vec(), 0, u64::MAX - 20);
        assert_eq!(c.get(&k, u64::MAX - 5), stale(true));
        assert_eq!(c.get(&k, u64::MAX), stale(false));
        assert_eq!(c.get(&k, u64::MAX - 10), stale(false));
        assert_eq!(c.get(&k, u64::MAX - 20), stale(false));
        assert_eq!(c.len(), 1);
    }

    /// Whether a fresh hit of `k` at `mono` asks for a prefetch. Panics unless the hit is fresh.
    fn prefetch_asked(c: &mut Cache, k: &Key, mono: u64) -> bool {
        match c.get(k, mono) {
            Some(Hit::Fresh { prefetch, .. }) => prefetch,
            other => panic!("not a fresh hit at {mono}: {other:?}"),
        }
    }

    #[test]
    fn no_prefetch_while_off() {
        let (mut c, k) = (Cache::new(10), key(1, false));
        c.insert(k.clone(), B.to_vec(), 300, 1000);
        for _ in 0..5 {
            assert!(!prefetch_asked(&mut c, &k, 1295));
        }
    }

    #[test]
    fn a_prefetch_is_asked_for_once_per_stored_answer_and_not_before_the_third_hit() {
        let (mut c, k) = (Cache::new(10), key(1, false));
        c.set_prefetch(true);
        c.insert(k.clone(), B.to_vec(), 300, 1000);
        // Inside the window of 30 seconds, but only the first and second hit.
        assert!(!prefetch_asked(&mut c, &k, 1280));
        assert!(!prefetch_asked(&mut c, &k, 1281));
        assert!(prefetch_asked(&mut c, &k, 1282));
        assert!(!prefetch_asked(&mut c, &k, 1283));
        assert!(!prefetch_asked(&mut c, &k, 1299));
        // Stored again, it is a new answer: hits count from 0, and it is asked for once more.
        c.insert(k.clone(), B.to_vec(), 300, 2000);
        assert!(!prefetch_asked(&mut c, &k, 2280));
        assert!(!prefetch_asked(&mut c, &k, 2281));
        assert!(prefetch_asked(&mut c, &k, 2282));
        assert!(!prefetch_asked(&mut c, &k, 2283));
    }

    #[test]
    fn a_prefetch_waits_for_its_window() {
        let (mut c, k) = (Cache::new(10), key(1, false));
        c.set_prefetch(true);
        c.insert(k.clone(), B.to_vec(), 300, 1000);
        // Many hits, all with more than 30 seconds left.
        for mono in 1000..1100 {
            assert!(!prefetch_asked(&mut c, &k, mono), "{mono}");
        }
        assert!(!prefetch_asked(&mut c, &k, 1269));
        // 30 seconds left: the first second of the window.
        assert!(prefetch_asked(&mut c, &k, 1270));
        assert!(!prefetch_asked(&mut c, &k, 1271));
    }

    #[test]
    fn the_prefetch_window_is_a_tenth_of_the_lifetime_within_2_and_60_seconds() {
        assert_eq!(
            (PREFETCH_MIN_HITS, PREFETCH_WINDOW_MIN, PREFETCH_WINDOW_MAX),
            (3, 2, 60)
        );
        // The lifetime, and the window it is to give; 10 is below what a stored answer gets
        // from an upstream, but `insert` takes any.
        for (lifetime, window) in [(10, 2), (30, 3), (300, 30), (600, 60), (86_400, 60)] {
            let (mut c, k) = (Cache::new(10), key(1, false));
            c.set_prefetch(true);
            c.insert(k.clone(), B.to_vec(), lifetime, 0);
            for _ in 0..3 {
                assert!(!prefetch_asked(&mut c, &k, 0));
            }
            let age = |left: u32| u64::from(lifetime - left);
            assert!(
                !prefetch_asked(&mut c, &k, age(window + 1)),
                "{lifetime}: one second before the window"
            );
            assert!(
                prefetch_asked(&mut c, &k, age(window)),
                "{lifetime}: window of {window}"
            );
        }
    }

    #[test]
    fn a_stale_hit_is_not_a_prefetch_and_clears_nothing() {
        let (mut c, k) = (Cache::new(10), key(1, false));
        c.set_prefetch(true);
        c.insert(k.clone(), B.to_vec(), 60, 0);
        assert_eq!(
            c.get(&k, 60),
            Some(Hit::Stale {
                body: B,
                refresh: true
            })
        );
        assert_eq!(
            c.get(&k, 61),
            Some(Hit::Stale {
                body: B,
                refresh: false
            })
        );
        assert_eq!(
            c.get(&k, 70),
            Some(Hit::Stale {
                body: B,
                refresh: true
            })
        );
    }

    #[test]
    fn the_hit_count_saturates() {
        let (mut c, k) = (Cache::new(10), key(1, false));
        c.set_prefetch(true);
        c.insert(k.clone(), B.to_vec(), 86_400, 0);
        // More hits than a `u16` counts, none of them with the window open.
        for _ in 0..70_000 {
            assert!(!prefetch_asked(&mut c, &k, 1));
        }
        assert!(prefetch_asked(&mut c, &k, 86_400 - 60));
    }
}
