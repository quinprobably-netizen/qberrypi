//! The decision for each client packet: drop it, answer it here, or ask an upstream.
//!
//! [`Resolver`] owns the block set, the cache, the pause deadline and the statistics. It moves
//! no packet itself: the caller carries out the [`Action`] it returns, and hands back each
//! packet an upstream sends for a [`Pending`] question to learn its [`UpstreamOutcome`].

use hickory_proto::op::{Message, MessageType, OpCode, Query};

use crate::answer::{blocked, error, local, relay};
use crate::cache::{CACHE_CAPACITY, Cache, Hit, Key, STALE_TTL, is_definitive, lifetime};
use crate::name::{MAX_NAME_LEN, normalize};
use crate::query::{Parsed, Question, ResponseCode, parse_query};
use crate::stats::{BLOCKED_NAMES_TRACKED, Outcome, QUERY_LOG_CAPACITY, Stats};
use crate::{BlockSet, ListClass, Now, Transport};

/// The name of the canary domain that Firefox asks for before it turns DNS over HTTPS on: a
/// resolver that answers it with NXDOMAIN tells the browser to leave its DNS to the network.
pub const DOH_CANARY: &str = "use-application-dns.net";

/// A query that was blocked as a threat, for the caller to raise an alert on.
///
/// It holds the name only: the caller knows which client asked, and the two are never logged
/// together.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThreatHit {
    /// The name asked for, as [`Stats`] records it: lower case, no trailing dot.
    pub name: Box<str>,
}

/// Which lists a client's query is held to. The caller says, for each query, from who asked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Filter {
    /// Every list: the ads and tracker lists, the configuration's deny names and the threat lists.
    All,
    /// The threat lists alone, for a client that is exempt from ad blocking: a name that only an
    /// ads list or a deny entry blocks is answered as if it were on no list, from the cache or an
    /// upstream. The DoH canary, the local answers and a pause apply as for any client.
    ThreatsOnly,
}

/// What the caller is to do with one client packet.
#[derive(Debug)]
pub enum Action {
    /// Send these bytes to the client.
    Reply(Vec<u8>),
    /// Ask an upstream, then send the client what the upstream's answer gives, or
    /// [`Pending::servfail`] once every upstream has failed.
    Forward(Pending),
    /// Send these bytes to the client now, and also ask an upstream to renew the stored answer:
    /// because it is stale, or, with [prefetch](Resolver::set_prefetch) on, because it is
    /// popular and about to expire ([`Pending::is_prefetch`]).
    ReplyAndRefresh(Vec<u8>, Pending),
    /// Send nothing.
    Drop,
}

/// A question on its way to an upstream, kept until the answer arrives.
#[derive(Clone, Debug)]
pub struct Pending {
    /// The question of the client that asked.
    question: Question,
    /// Whether that client was already answered, from a cache entry.
    refresh: bool,
    /// Whether the entry was fresh, and renewed ahead of its end: always with `refresh`.
    prefetch: bool,
}

impl Pending {
    /// `question` on its way upstream: as a refresh, or for its client who waits.
    fn new(question: Question, refresh: bool) -> Self {
        Self {
            question,
            refresh,
            prefetch: false,
        }
    }

    /// `question` on its way upstream to renew a fresh entry that is about to expire.
    fn prefetch(question: Question) -> Self {
        Self {
            question,
            refresh: true,
            prefetch: true,
        }
    }

    /// The query to send upstream under `id`; if it is empty, do not send; send the client what
    /// [`Pending::servfail`] gives, if anything.
    ///
    /// It is empty only if the question cannot be encoded, which a question decoded from a
    /// client's packet does not cause.
    pub fn upstream_query(&self, id: u16) -> Vec<u8> {
        self.question.upstream_query(id)
    }

    /// The name asked for, as [`Stats`] records it: lower case, no trailing dot, `""` for the root.
    pub fn name(&self) -> &str {
        self.question.name()
    }

    /// The record type asked for, as its number.
    pub fn qtype(&self) -> u16 {
        self.question.qtype()
    }

    /// Whether this renews a cache entry, stale or about to expire, with no client waiting for
    /// the answer. A [prefetch](Pending::is_prefetch) is one.
    pub fn is_refresh(&self) -> bool {
        self.refresh
    }

    /// Whether this renews an entry that was still fresh, because it is popular and about to
    /// expire, rather than one that was stale. Such a question is also
    /// [`is_refresh`](Pending::is_refresh), so its answer gives [`UpstreamOutcome::Refreshed`].
    /// The caller may skip it: the entry then goes stale and a stale hit asks for the renewal.
    pub fn is_prefetch(&self) -> bool {
        self.prefetch
    }

    /// The SERVFAIL reply for the waiting client once every upstream has failed; `None` for a
    /// refresh, whose client was already answered.
    pub fn servfail(&self) -> Option<Vec<u8>> {
        (!self.refresh).then(|| error(&self.question, ResponseCode::ServFail))
    }
}

/// What the caller is to do with one packet from an upstream.
#[derive(Debug, PartialEq, Eq)]
pub enum UpstreamOutcome {
    /// Send these bytes to the waiting client.
    Reply(Vec<u8>),
    /// The packet answered a refresh, and was stored if it may be: there is nothing to send.
    Refreshed,
    /// The answer was truncated: ask the same upstream again over TCP.
    RetryOverTcp,
    /// Not an answer to this question: ignore the packet and keep waiting.
    Mismatch,
}

/// How a question is answered, before the [`Action`] takes the question over.
enum Decision {
    /// With these bytes.
    Reply(Vec<u8>),
    /// With these bytes, from a cache entry that an upstream is to renew: a stale one, or, if
    /// the flag is set, a fresh one that is to be prefetched.
    ReplyAndRefresh(Vec<u8>, bool),
    /// By an upstream.
    Forward,
}

/// Decides every client query: blocked, answered here, cached, stale, or forwarded.
///
/// Its memory is bounded whatever the traffic: the cache, the query log and the blocked-name
/// counts each hold a fixed number of entries at most, and the history a fixed number of buckets.
/// The worst cases, which are what a memory budget starts from, are at the longest names a client
/// can send:
///
/// - The cache, about 62 MB: 10,000 entries, each with a body of up to 4,096 bytes and a key of
///   up to 1,003 bytes (a name of 255 bytes on the wire with every byte escaped) that is stored
///   twice, once in the map and once in its slot. Ordinary names take a small part of this.
/// - The query log, about 50 MB: 50,000 entries of names up to 1,003 bytes, plus a few MB for the
///   entries themselves.
/// - The blocked-name counts, under 1 MB: 1,024 names of at most 253 bytes, as only a name that
///   could be on a list is blocked, each with 24 hourly counts.
/// - The history, about 6 KB: 144 ten-minute buckets of 40 bytes each, always all there.
///
/// The block set has no cap of its own: whoever builds it caps the size of the lists.
pub struct Resolver {
    /// The names to block.
    blockset: BlockSet,
    /// Upstream answers by name, type and DO bit.
    cache: Cache,
    /// The counters and the query log.
    stats: Stats,
    /// The monotonic second at which blocking applies again; `None` when no pause was set.
    paused_until: Option<u64>,
    /// Whether [`DOH_CANARY`] gets NXDOMAIN whatever the lists say.
    doh_canary: bool,
}

impl Resolver {
    /// A resolver that blocks the names of `blockset`, with an empty cache and empty statistics.
    pub fn new(blockset: BlockSet) -> Self {
        Self {
            blockset,
            cache: Cache::new(CACHE_CAPACITY),
            stats: Stats::new(QUERY_LOG_CAPACITY, BLOCKED_NAMES_TRACKED),
            paused_until: None,
            doh_canary: true,
        }
    }

    /// Replaces the block set; the cache, the pause and the statistics stay as they are. The old
    /// set is dropped here, which frees its buffers: a caller that holds a lock on the resolver,
    /// and a set of tens of megabytes, uses [`replace_blockset`](Self::replace_blockset) instead.
    pub fn set_blockset(&mut self, blockset: BlockSet) {
        self.blockset = blockset;
    }

    /// Replaces the block set as [`set_blockset`](Self::set_blockset) does, and gives the old one
    /// back instead of dropping it, so that the caller frees it where and when it likes: after
    /// the lock on the resolver is let go, and off the thread that serves the queries. Nothing
    /// here moves more than the set's handful of buffer handles.
    pub fn replace_blockset(&mut self, blockset: BlockSet) -> BlockSet {
        std::mem::replace(&mut self.blockset, blockset)
    }

    /// Decides one packet from a client. Never panics, whatever the bytes.
    ///
    /// This is [`handle_query_threat`](Self::handle_query_threat) without the report of a threat;
    /// a threat name is blocked and counted as one all the same.
    pub fn handle_query(&mut self, packet: &[u8], transport: Transport, now: Now) -> Action {
        self.handle_query_threat(packet, transport, now).0
    }

    /// Decides one packet from a client, and says whether it was blocked as a threat. Never
    /// panics, whatever the bytes.
    ///
    /// The first of these that applies decides:
    ///
    /// 1. A packet that is not a query to decide is dropped or answered with an error.
    /// 2. A name that is answered here, such as `localhost` or a single-label name asked for an
    ///    address, gets that answer.
    /// 3. The DoH canary, [`DOH_CANARY`], gets NXDOMAIN for any type, unless the canary was
    ///    turned off with [`set_doh_canary`](Self::set_doh_canary). It is counted as answered
    ///    here, not as blocked, so a deny entry for it changes nothing.
    /// 4. A blocked name gets the blocked reply, unless blocking is paused. If the block is of
    ///    a threat list, the packet's [`ThreatHit`] comes back with it, and the query is also
    ///    counted in [`Counts::blocked_threat`](crate::Counts::blocked_threat). For a client held
    ///    to [`Filter::ThreatsOnly`] ([`handle_query_filtered`](Self::handle_query_filtered)) only
    ///    a block of a threat list applies, and any other name goes on to step 5.
    /// 5. A cached answer is sent, every TTL being the lifetime it has left.
    /// 6. A stale one is sent with short TTLs, and an upstream is asked to renew it unless one
    ///    was asked within the last seconds.
    /// 7. Anything else is forwarded.
    ///
    /// With [prefetch](Self::set_prefetch) on, a cached answer of step 5 that is popular and about
    /// to expire is sent as usual, with an upstream also asked to renew it: the
    /// [`Action::ReplyAndRefresh`] holds a [`Pending`] with [`Pending::is_prefetch`]. The query is
    /// still counted as a cache hit.
    ///
    /// Every query decided in steps 2 to 7 is counted and logged; those of step 1 are not. The
    /// hit is `None` for every packet but one blocked as a threat, and allocates nothing then.
    pub fn handle_query_threat(
        &mut self,
        packet: &[u8],
        transport: Transport,
        now: Now,
    ) -> (Action, Option<ThreatHit>) {
        self.handle_query_filtered(packet, transport, now, Filter::All)
    }

    /// Decides one packet from a client that is held to the lists of `filter`, as
    /// [`handle_query_threat`](Self::handle_query_threat) does, which is this with
    /// [`Filter::All`]. Never panics, whatever the bytes.
    ///
    /// With [`Filter::ThreatsOnly`] a name that only an ads list or a deny entry blocks is not
    /// blocked: it is answered from the cache or forwarded, and counted as the cache hit or the
    /// forward that it was. A threat is blocked and reported as for any client. What such a query
    /// stores in the cache is never served to a client held to every list, as the block check
    /// comes before the cache for that client.
    pub fn handle_query_filtered(
        &mut self,
        packet: &[u8],
        transport: Transport,
        now: Now,
        filter: Filter,
    ) -> (Action, Option<ThreatHit>) {
        let question = match parse_query(packet, transport) {
            Parsed::Ok(question) => question,
            Parsed::Refuse(question, rcode) => {
                return (Action::Reply(error(&question, rcode)), None);
            }
            Parsed::HeaderOnly(header) => return (Action::Reply(header.to_vec()), None),
            Parsed::Drop => return (Action::Drop, None),
        };
        let (outcome, decision, threat) = self.decide(&question, now, filter);
        self.stats
            .record(question.name(), question.qtype(), outcome, now);
        let hit = threat.then(|| {
            self.stats.record_threat(now);
            ThreatHit {
                name: question.name().into(),
            }
        });
        let action = match decision {
            Decision::Reply(reply) => Action::Reply(reply),
            Decision::ReplyAndRefresh(reply, false) => {
                Action::ReplyAndRefresh(reply, Pending::new(question, true))
            }
            Decision::ReplyAndRefresh(reply, true) => {
                Action::ReplyAndRefresh(reply, Pending::prefetch(question))
            }
            Decision::Forward => Action::Forward(Pending::new(question, false)),
        };
        (action, hit)
    }

    /// Takes in one packet that an upstream sent over `via` for `pending`. Never panics,
    /// whatever the bytes.
    ///
    /// The first of these that applies decides:
    ///
    /// 1. A packet that cannot be read, is not a response, or does not hold exactly the pending
    ///    question — the same name but for the case of its letters, the same type and class —
    ///    is a mismatch, and changes nothing.
    /// 2. An answer that was truncated on its way over UDP is to be asked for again over TCP.
    /// 3. An answer that may be cached is stored for its lifetime from `now.mono_secs`, under
    ///    the pending question's name, type and DO bit, and without the upstream's OPT record.
    ///    A NOERROR or NXDOMAIN answer that cannot be stored (too long, or a negative one
    ///    without an SOA) still removes the answer stored under that key, which it shows to be
    ///    out of date; a failure such as SERVFAIL or REFUSED leaves it to be served stale.
    /// 4. For a refresh there is nothing to send. A waiting client gets the answer under its
    ///    own ID and spelling of the name; every TTL is the lifetime if the answer was stored,
    ///    and the upstream's own if not.
    ///
    /// Nothing is counted or logged: the query was, when it was decided. The caller checks the
    /// packet's ID and source address; this checks the question.
    pub fn handle_upstream(
        &mut self,
        pending: &Pending,
        packet: &[u8],
        via: Transport,
        now: Now,
    ) -> UpstreamOutcome {
        let question = &pending.question;
        let Ok(mut answer) = Message::from_vec(packet) else {
            return UpstreamOutcome::Mismatch;
        };
        if !is_response_to(&answer, question.query()) {
            return UpstreamOutcome::Mismatch;
        }
        if answer.metadata.truncation && via == Transport::Udp {
            return UpstreamOutcome::RetryOverTcp;
        }
        // The OPT record is about the one exchange with the upstream, and no part of the answer.
        answer.edns = None;
        let stored_for = self.store(question, &answer, now);
        if pending.refresh {
            UpstreamOutcome::Refreshed
        } else {
            UpstreamOutcome::Reply(relay(question, &answer, stored_for))
        }
    }

    /// Pauses blocking until the monotonic clock reaches `mono_secs`, in place of any pause
    /// already set.
    pub fn pause_until(&mut self, mono_secs: u64) {
        self.paused_until = Some(mono_secs);
    }

    /// Ends a pause now.
    pub fn resume(&mut self) {
        self.paused_until = None;
    }

    /// Turns prefetch on or off; it is off until set, and then a cached answer is never renewed
    /// before it goes stale. On, a popular answer that is about to expire is renewed once per
    /// stored answer, by the [`Action::ReplyAndRefresh`] of the hit that finds it so. Popular
    /// means at least 3 fresh hits since it was stored, that hit included; about to expire means
    /// a lifetime left of at most a tenth of its lifetime, held to between 2 and 60 seconds.
    pub fn set_prefetch(&mut self, on: bool) {
        self.cache.set_prefetch(on);
    }

    /// Turns the DoH canary on or off; it is on until set. While it is on, [`DOH_CANARY`] gets
    /// NXDOMAIN whatever the block set and a pause say; off, it is any other name.
    pub fn set_doh_canary(&mut self, on: bool) {
        self.doh_canary = on;
    }

    /// The monotonic second at which the running pause ends; `None` when blocking applies at
    /// `now`. Only `now.mono_secs` is read.
    pub fn paused_until(&self, now: Now) -> Option<u64> {
        self.paused_until.filter(|&until| now.mono_secs < until)
    }

    /// Whether the block set blocks `name`, whether or not blocking is paused: what a query for
    /// it would get if blocking were on. The allow rules apply as they do to a query.
    ///
    /// `name` may be spelled as the log holds it or as a client wrote it: it is lower-cased and
    /// loses one trailing dot first, in a buffer on the stack, so nothing is allocated. A name
    /// that cannot be on a list (a character outside `a-z 0-9 - _`, an empty label, a last label
    /// of digits only, or more than 253 bytes) is not blocked, as in [`Resolver::handle_query`].
    pub fn lists(&self, name: &str) -> bool {
        let mut buf = [0; MAX_NAME_LEN];
        normalize(name.as_bytes(), &mut buf).is_some_and(|name| self.blockset.is_blocked(name))
    }

    /// Sets local time minus UTC in seconds, which places the midnight where "today" starts.
    pub fn set_utc_offset(&mut self, secs: i32) {
        self.stats.set_utc_offset(secs);
    }

    /// The counters, the most recently blocked name and the query log.
    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    /// How many answers the cache holds, stale ones included.
    pub fn cache_len(&self) -> usize {
        self.cache.len()
    }

    /// Steps 2 to 7 of [`Resolver::handle_query_threat`] for a client held to `filter`, and
    /// whether the block of step 4 was of a threat. The canary and block checks come before the
    /// cache, so a blocked name is never answered from it and never touches it.
    fn decide(
        &mut self,
        question: &Question,
        now: Now,
        filter: Filter,
    ) -> (Outcome, Decision, bool) {
        if let Some(reply) = local(question) {
            return (Outcome::Local, Decision::Reply(reply), false);
        }
        if self.doh_canary && question.name() == DOH_CANARY {
            let reply = error(question, ResponseCode::NXDomain);
            return (Outcome::Local, Decision::Reply(reply), false);
        }
        if let Some(class) = self.block_class(question, now, filter) {
            let threat = class == ListClass::Threat;
            return (Outcome::Blocked, Decision::Reply(blocked(question)), threat);
        }
        let (outcome, decision) = self
            .cached(question, now)
            .unwrap_or((Outcome::Forwarded, Decision::Forward));
        (outcome, decision, false)
    }

    /// The class of the block that `question` is to get at `now` for a client held to `filter`,
    /// or `None` if it is to get none: blocking is paused, or the name is not one the block set
    /// could hold, or does not block, or blocks only as an ad and the client is held to threats
    /// only.
    fn block_class(&self, question: &Question, now: Now, filter: Filter) -> Option<ListClass> {
        if self.paused_until(now).is_some() {
            return None;
        }
        self.blockset
            .verdict(question.block_key()?)
            .filter(|&class| filter == Filter::All || class == ListClass::Threat)
    }

    /// The reply to `question` from the cache, or `None` on a miss. A stored answer that cannot
    /// be decoded counts as a miss.
    fn cached(&mut self, question: &Question, now: Now) -> Option<(Outcome, Decision)> {
        let (body, ttl, outcome, refresh, prefetch) =
            match self.cache.get(&cache_key(question), now.mono_secs)? {
                Hit::Fresh {
                    body,
                    ttl,
                    prefetch,
                } => (body, ttl, Outcome::Cached, false, prefetch),
                Hit::Stale { body, refresh } => (body, STALE_TTL, Outcome::Stale, refresh, false),
            };
        let stored = Message::from_vec(body).ok()?;
        let reply = relay(question, &stored, Some(ttl));
        let decision = if refresh || prefetch {
            Decision::ReplyAndRefresh(reply, prefetch)
        } else {
            Decision::Reply(reply)
        };
        Some((outcome, decision))
    }

    /// Stores `answer` as the answer to `question` from `now.mono_secs`, and returns the seconds
    /// it is fresh for. `None` if nothing was stored: the answer may not be cached, cannot be
    /// encoded, or is longer than the cache takes.
    ///
    /// A definitive answer takes the place of what is stored for the question, even when it is
    /// the one that cannot be stored: the stored one is known to be out of date, and must not be
    /// served stale for another hour. A failure leaves it, which is what serving stale is for.
    fn store(&mut self, question: &Question, answer: &Message, now: Now) -> Option<u32> {
        let key = cache_key(question);
        if is_definitive(answer) {
            self.cache.remove(&key);
        }
        let fresh_for = lifetime(answer)?;
        // The body is the answer encoded again, and may come out longer than it arrived: hickory
        // compresses only the first 120 names of a message (`COMPRESSED_NAME_LIMIT`) and keeps at
        // most 64 label pointers to compress against (`COMPRESSION_CANDIDATE_LIMIT`). So a large
        // answer can come out over the cap and is not cached. An answer that large is over the
        // 1,232 bytes of a UDP reply, so it normally came over TCP and is truncated for every UDP
        // client anyway: the cost is a miss, and every query for it is forwarded.
        let body = answer.to_vec().ok()?;
        self.cache
            .insert(key, body, fresh_for, now.mono_secs)
            .then_some(fresh_for)
    }
}

/// Whether `packet` is a response to `asked` and to nothing else: a response to a query, whose
/// one question has the same name, type and class. hickory compares names label by label and
/// without regard to the case of ASCII letters, so a label that holds a dot never equals two
/// labels.
fn is_response_to(packet: &Message, asked: &Query) -> bool {
    let [answered] = packet.queries.as_slice() else {
        return false;
    };
    packet.metadata.message_type == MessageType::Response
        && packet.metadata.op_code == OpCode::Query
        && answered.name == asked.name
        && answered.query_type == asked.query_type
        && answered.query_class == asked.query_class
}

/// What the answer to `question` is stored under: its name in lower case, its type and its DO
/// bit, and nothing else.
fn cache_key(question: &Question) -> Key {
    Key {
        name: question.name().into(),
        qtype: question.qtype(),
        dnssec_ok: question.dnssec_ok(),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use hickory_proto::op::Edns;
    use hickory_proto::rr::rdata::TXT;
    use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsCode, EdnsOption};
    use hickory_proto::rr::{RData, Record};

    use super::*;
    use crate::testutil::{
        Q_AAAA_EDNS, Q_DIG, Q_DO, Q_MIXED, Q_NODATA, Q_PLAIN, R_A, R_NODATA, R_NXDOMAIN, Rng,
        decode, query, unhex,
    };
    use crate::{BlockSetBuilder, Counts, ListClass};

    /// The query of Review Focus 2: `Q_PLAIN` with the one label `a.b`, 3 bytes, put before
    /// `example.com`.
    const Q_DOTTED: &str = "12340100000100000000000003612e62076578616d706c6503636f6d0000010001";

    /// `example.com` A as `Pending::upstream_query(0xbeef)` must build it.
    const UPSTREAM_PLAIN: &str =
        "beef01000001000000000001076578616d706c6503636f6d000001000100002904d0000000000000";

    fn resolver() -> Resolver {
        let mut b = BlockSetBuilder::new();
        b.add_list(b"0.0.0.0 ads.example.com\n||tracker.example.net^\n");
        b.allow("ok.tracker.example.net").unwrap();
        Resolver::new(b.build())
    }

    /// A resolver with `ads.example.com` on an ads list and `bad.example.net`, with its
    /// subdomains, on a threat list.
    fn threat_resolver() -> Resolver {
        let mut b = BlockSetBuilder::new();
        b.add_list(b"0.0.0.0 ads.example.com\n");
        b.add_list_as(b"||bad.example.net^\n", ListClass::Threat);
        Resolver::new(b.build())
    }

    /// `Counts` of a day in which the only queries were `blocked` blocked ones, `threats` of
    /// them for a threat name.
    fn blocked_counts(blocked: u64, threats: u64) -> Counts {
        Counts {
            queries: blocked,
            blocked,
            blocked_threat: threats,
            ..Counts::default()
        }
    }

    fn at(mono_secs: u64) -> Now {
        Now {
            mono_secs,
            unix_secs: 1_800_000_000 + mono_secs,
        }
    }

    fn ask(r: &mut Resolver, name: &str, qtype: u16, mono: u64) -> Action {
        r.handle_query(&query(7, name, qtype), Transport::Udp, at(mono))
    }

    fn reply(a: Action) -> Vec<u8> {
        match a {
            Action::Reply(b) => b,
            _ => panic!("not a plain reply"),
        }
    }

    fn is_blocked_reply(b: &[u8]) -> bool {
        let m = decode(b);
        m.answers.len() == 1 && m.answers[0].ttl == 2 && m.answers[0].data.to_string() == "0.0.0.0"
    }

    fn ttls(b: &[u8]) -> Vec<u32> {
        let m = decode(b);
        m.answers
            .iter()
            .chain(&m.authorities)
            .map(|r| r.ttl)
            .collect()
    }

    fn key(name: &str, qtype: u16, dnssec_ok: bool) -> Key {
        Key {
            name: name.into(),
            qtype,
            dnssec_ok,
        }
    }

    /// Puts the captured answer `R_A`, two A records, in the cache as the answer to `name` A
    /// without the DO bit: stored at 1000 with a lifetime of 215 seconds, so stale from 1215
    /// and gone at 4815.
    fn store_a(r: &mut Resolver, name: &str) {
        r.cache.insert(key(name, 1, false), unhex(R_A), 215, 1000);
    }

    /// The question that `packet`, sent over UDP at `mono`, puts on its way upstream. Panics
    /// unless the query is forwarded.
    fn forwarded(r: &mut Resolver, packet: &[u8], mono: u64) -> Pending {
        match r.handle_query(packet, Transport::Udp, at(mono)) {
            Action::Forward(p) => p,
            _ => panic!("not forwarded"),
        }
    }

    /// Asks for `example.com` A at 1000 and takes in the captured answer `R_A`, as `store_a`
    /// seeds it but through both entry points: stored at 1000 with a lifetime of 215 seconds,
    /// and one query counted as forwarded.
    fn cached_example(r: &mut Resolver) {
        let p = forwarded(r, &unhex(Q_PLAIN), 1000);
        assert_eq!(
            r.handle_upstream(&p, &unhex(R_A), Transport::Udp, at(1000)),
            UpstreamOutcome::Reply(unhex(R_A))
        );
    }

    /// `cached_example`, then a query at 1215 that finds the answer stale: the refresh it asks for.
    fn stale_refresh(r: &mut Resolver) -> Pending {
        cached_example(r);
        let Action::ReplyAndRefresh(_, p) = ask(r, "example.com", 1, 1215) else {
            panic!("not a reply with a refresh")
        };
        p
    }

    /// An answer an upstream could give to `p`: the query sent to it under `id`, turned into a
    /// response that holds the two A records of `R_A`. It keeps that query's OPT record.
    fn answer_for(p: &Pending, id: u16) -> Message {
        let mut answer = decode(&p.upstream_query(id));
        answer.metadata.message_type = MessageType::Response;
        answer.metadata.recursion_available = true;
        answer.answers = decode(&unhex(R_A)).answers;
        answer
    }

    /// The bytes of the reply that an upstream's packet gives the waiting client. Panics on any
    /// other outcome.
    fn relayed(outcome: UpstreamOutcome) -> Vec<u8> {
        match outcome {
            UpstreamOutcome::Reply(b) => b,
            other => panic!("not a reply: {other:?}"),
        }
    }

    #[test]
    fn a_blocked_name_gets_the_blocked_reply_and_is_counted() {
        let mut r = resolver();
        assert!(is_blocked_reply(&reply(ask(
            &mut r,
            "ads.example.com",
            1,
            100
        ))));
        assert_eq!(
            r.stats().today(at(100)),
            Counts {
                queries: 1,
                blocked: 1,
                blocked_threat: 0,
                cache_hits: 0,
                forwarded: 0
            }
        );
        let last = r.stats().last_blocked(at(100)).unwrap();
        assert_eq!(
            (last.name.as_str(), last.unix_secs, last.count_24h),
            ("ads.example.com", 1_800_000_100, 1)
        );
        let entry = r.stats().recent(1).next().unwrap();
        assert_eq!(
            (&*entry.name, entry.qtype, entry.outcome),
            ("ads.example.com", 1, Outcome::Blocked)
        );
    }

    #[test]
    fn a_threat_name_is_blocked_counted_and_reported() {
        let mut r = threat_resolver();
        let (action, hit) =
            r.handle_query_threat(&query(7, "x.bad.example.net", 1), Transport::Udp, at(100));
        assert!(is_blocked_reply(&reply(action)));
        assert_eq!(
            hit,
            Some(ThreatHit {
                name: "x.bad.example.net".into()
            })
        );
        assert_eq!(r.stats().today(at(100)), blocked_counts(1, 1));
        assert_eq!(r.stats().total(), blocked_counts(1, 1));
        let entry = r.stats().recent(1).next().unwrap();
        assert_eq!(
            (&*entry.name, entry.outcome),
            ("x.bad.example.net", Outcome::Blocked)
        );

        // The name is reported as recorded: lower case, whatever the client's spelling.
        let (_, hit) =
            r.handle_query_threat(&query(8, "X.Bad.EXAMPLE.net", 28), Transport::Udp, at(101));
        assert_eq!(hit.unwrap().name.as_ref(), "x.bad.example.net");

        // `handle_query` blocks and counts the same, and drops the hit.
        assert!(is_blocked_reply(&reply(ask(
            &mut r,
            "bad.example.net",
            1,
            102
        ))));
        assert_eq!(r.stats().today(at(102)), blocked_counts(3, 3));
        assert_eq!(r.stats().total(), blocked_counts(3, 3));
    }

    #[test]
    fn an_ads_block_reports_no_threat() {
        let mut r = threat_resolver();
        let (action, hit) =
            r.handle_query_threat(&query(7, "ads.example.com", 1), Transport::Udp, at(100));
        assert!(is_blocked_reply(&reply(action)));
        assert_eq!(hit, None);
        assert_eq!(r.stats().today(at(100)), blocked_counts(1, 0));
        assert_eq!(r.stats().total(), blocked_counts(1, 0));
        // Neither does a forwarded or a malformed query.
        let (action, hit) =
            r.handle_query_threat(&query(7, "example.org", 1), Transport::Udp, at(101));
        assert!(matches!(action, Action::Forward(_)));
        assert_eq!(hit, None);
        let (action, hit) = r.handle_query_threat(&[1, 2, 3], Transport::Udp, at(102));
        assert!(matches!(action, Action::Drop));
        assert_eq!(hit, None);
        assert_eq!(r.stats().total().blocked_threat, 0);
    }

    /// What `r` decides for `name` of `qtype` at `mono`, for a client held to `filter`, and the
    /// threat it reports.
    fn ask_as(
        r: &mut Resolver,
        filter: Filter,
        name: &str,
        qtype: u16,
        mono: u64,
    ) -> (Action, Option<ThreatHit>) {
        r.handle_query_filtered(&query(7, name, qtype), Transport::Udp, at(mono), filter)
    }

    #[test]
    fn a_client_held_to_threats_only_gets_an_ads_name_from_an_upstream() {
        let mut r = threat_resolver();
        let (action, hit) = ask_as(&mut r, Filter::ThreatsOnly, "ads.example.com", 1, 100);
        let Action::Forward(p) = action else {
            panic!("not forwarded: {action:?}")
        };
        assert_eq!(
            (p.name(), p.qtype(), p.is_refresh()),
            ("ads.example.com", 1, false)
        );
        assert_eq!(hit, None);
        // It is counted as what it was, a forwarded query, and never as a block.
        let forwarded = Counts {
            queries: 1,
            forwarded: 1,
            ..Counts::default()
        };
        assert_eq!(r.stats().today(at(100)), forwarded);
        assert_eq!(r.stats().total(), forwarded);
        assert!(r.stats().last_blocked(at(100)).is_none());
        let entry = r.stats().recent(1).next().unwrap();
        assert_eq!(
            (&*entry.name, entry.outcome),
            ("ads.example.com", Outcome::Forwarded)
        );
        // `All` is what `handle_query` does: the same name is blocked.
        let (action, hit) = ask_as(&mut r, Filter::All, "ads.example.com", 1, 101);
        assert!(is_blocked_reply(&reply(action)));
        assert_eq!(hit, None);
        assert_eq!(r.stats().total().blocked, 1);
    }

    #[test]
    fn a_client_held_to_threats_only_still_has_its_threats_blocked_and_reported() {
        let mut r = threat_resolver();
        let (action, hit) = ask_as(&mut r, Filter::ThreatsOnly, "X.Bad.example.NET", 28, 100);
        let blocked = decode(&reply(action));
        assert_eq!(blocked.answers.len(), 1);
        assert_eq!(
            (blocked.answers[0].ttl, blocked.answers[0].data.to_string()),
            (2, "::".to_owned())
        );
        assert_eq!(
            hit,
            Some(ThreatHit {
                name: "x.bad.example.net".into()
            })
        );
        assert_eq!(r.stats().total(), blocked_counts(1, 1));
        let (action, _) = ask_as(&mut r, Filter::ThreatsOnly, "bad.example.net", 1, 101);
        assert!(is_blocked_reply(&reply(action)));
        assert_eq!(r.stats().total(), blocked_counts(2, 2));
    }

    #[test]
    fn a_deny_entry_does_not_block_a_client_held_to_threats_only() {
        let mut b = BlockSetBuilder::new();
        b.deny("tracker.example.org").unwrap();
        b.add_list_as(b"||bad.example.net^\n", ListClass::Threat);
        let mut r = Resolver::new(b.build());
        let (action, hit) = ask_as(&mut r, Filter::ThreatsOnly, "x.tracker.example.org", 1, 1);
        assert!(matches!(action, Action::Forward(_)));
        assert_eq!(hit, None);
        let (action, _) = ask_as(&mut r, Filter::All, "x.tracker.example.org", 1, 1);
        assert!(is_blocked_reply(&reply(action)));
    }

    #[test]
    fn a_client_held_to_threats_only_keeps_the_canary_and_the_local_answers() {
        let mut b = BlockSetBuilder::new();
        b.deny(DOH_CANARY).unwrap();
        let mut r = Resolver::new(b.build());
        let (action, hit) = ask_as(&mut r, Filter::ThreatsOnly, DOH_CANARY, 1, 1);
        let b = reply(action);
        assert_eq!((b[3] & 0x0f, decode(&b).answers.len(), hit), (3, 0, None));
        let (action, _) = ask_as(&mut r, Filter::ThreatsOnly, "localhost", 1, 1);
        assert_eq!(
            decode(&reply(action)).answers[0].data.to_string(),
            "127.0.0.1"
        );
        assert_eq!(r.stats().total().blocked, 0);
        assert_eq!(r.stats().recent(1).next().unwrap().outcome, Outcome::Local);
        // With the canary off it is an ordinary name, and only an ads block, which is skipped.
        r.set_doh_canary(false);
        let (action, _) = ask_as(&mut r, Filter::ThreatsOnly, DOH_CANARY, 1, 2);
        assert!(matches!(action, Action::Forward(_)));
    }

    #[test]
    fn a_pause_forwards_a_threat_for_a_client_held_to_threats_only_as_for_any_other() {
        let mut r = threat_resolver();
        r.pause_until(1300);
        let (action, hit) = ask_as(&mut r, Filter::ThreatsOnly, "x.bad.example.net", 1, 1299);
        assert!(matches!(action, Action::Forward(_)));
        assert_eq!(hit, None);
        let (_, hit) = ask_as(&mut r, Filter::ThreatsOnly, "x.bad.example.net", 1, 1300);
        assert!(hit.is_some());
    }

    // The block check comes before the cache for every client that is held to every list, so an
    // answer that a client held to threats only had stored is never served to one of them.
    #[test]
    fn an_ads_answer_cached_for_a_client_held_to_threats_only_never_reaches_any_other() {
        let mut r = resolver();
        let (action, _) = ask_as(&mut r, Filter::ThreatsOnly, "ads.example.com", 1, 1000);
        let Action::Forward(p) = action else {
            panic!("not forwarded: {action:?}")
        };
        let answer = answer_for(&p, 1).to_vec().unwrap();
        relayed(r.handle_upstream(&p, &answer, Transport::Udp, at(1000)));
        assert_eq!(r.cache_len(), 1);

        // The same client asks again: the answer it stored, as a cache hit.
        let (action, _) = ask_as(&mut r, Filter::ThreatsOnly, "ads.example.com", 1, 1001);
        assert_eq!(decode(&reply(action)).answers.len(), 2);
        // A client held to every list asks next: blocked, whatever the cache holds.
        assert!(is_blocked_reply(&reply(ask(
            &mut r,
            "ads.example.com",
            1,
            1002
        ))));
        let (action, _) = ask_as(&mut r, Filter::All, "ads.example.com", 1, 1003);
        assert!(is_blocked_reply(&reply(action)));
        // The blocks did not touch the stored answer: the first client still gets it.
        let (action, _) = ask_as(&mut r, Filter::ThreatsOnly, "ads.example.com", 1, 1004);
        assert_eq!(decode(&reply(action)).answers.len(), 2);
        assert_eq!(
            r.stats().total(),
            Counts {
                queries: 5,
                blocked: 2,
                blocked_threat: 0,
                cache_hits: 2,
                forwarded: 1
            }
        );
    }

    #[test]
    fn a_paused_resolver_reports_no_threat() {
        let mut r = threat_resolver();
        r.pause_until(1300);
        let (action, hit) =
            r.handle_query_threat(&query(7, "x.bad.example.net", 1), Transport::Udp, at(1299));
        assert!(matches!(action, Action::Forward(_)));
        assert_eq!(hit, None);
        assert_eq!(
            r.stats().total(),
            Counts {
                queries: 1,
                forwarded: 1,
                ..Counts::default()
            }
        );
        // Once the pause ends the same name is a threat again.
        let (_, hit) =
            r.handle_query_threat(&query(7, "x.bad.example.net", 1), Transport::Udp, at(1300));
        assert!(hit.is_some());
    }

    #[test]
    fn the_doh_canary_gets_nxdomain() {
        assert_eq!(DOH_CANARY, "use-application-dns.net");
        let mut r = resolver();
        for qtype in [1, 28, 65] {
            let q = query(7, DOH_CANARY, qtype);
            let b = reply(r.handle_query(&q, Transport::Udp, at(1)));
            assert_eq!(b[3] & 0x0f, 3, "type {qtype}");
            assert_eq!(decode(&b).queries, decode(&q).queries, "type {qtype}");
            assert!(decode(&b).answers.is_empty(), "type {qtype}");
        }
        // The case of the letters does not matter.
        let b = reply(ask(&mut r, "Use-Application-DNS.net", 1, 1));
        assert_eq!(b[3] & 0x0f, 3);
        assert_eq!(
            r.stats().total(),
            Counts {
                queries: 4,
                ..Counts::default()
            }
        );
        assert_eq!(r.stats().recent(1).next().unwrap().outcome, Outcome::Local);

        // On the deny list it still gets NXDOMAIN, not the blocked reply that Firefox would
        // take as "keep DoH on".
        let mut b = BlockSetBuilder::new();
        b.deny(DOH_CANARY).unwrap();
        let mut r = Resolver::new(b.build());
        let b = reply(ask(&mut r, DOH_CANARY, 1, 1));
        assert_eq!((b[3] & 0x0f, decode(&b).answers.len()), (3, 0));
        assert_eq!(r.stats().total().blocked, 0);

        // A name under it is an ordinary name.
        let mut r = resolver();
        assert!(matches!(
            ask(&mut r, "sub.use-application-dns.net", 1, 1),
            Action::Forward(_)
        ));
    }

    #[test]
    fn the_canary_can_be_turned_off() {
        let mut r = resolver();
        r.set_doh_canary(false);
        assert!(matches!(ask(&mut r, DOH_CANARY, 1, 1), Action::Forward(_)));
        r.set_doh_canary(true);
        assert_eq!(reply(ask(&mut r, DOH_CANARY, 1, 2))[3] & 0x0f, 3);

        // Off, the name is as any other: a deny entry blocks it.
        let mut b = BlockSetBuilder::new();
        b.deny(DOH_CANARY).unwrap();
        let mut r = Resolver::new(b.build());
        r.set_doh_canary(false);
        assert!(is_blocked_reply(&reply(ask(&mut r, DOH_CANARY, 1, 1))));
    }

    // The upstream's OPT, whatever it holds, is dropped: the client gets its own, with no options.
    #[test]
    fn a_relayed_answer_carries_no_upstream_ecs() {
        let mut r = resolver();
        let p = forwarded(&mut r, &unhex(Q_DIG), 1000);
        let mut answer = answer_for(&p, 1);
        let subnet = ClientSubnet::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)), 24, 24);
        answer
            .edns
            .as_mut()
            .unwrap()
            .options_mut()
            .insert(EdnsOption::Subnet(subnet));
        let bytes = answer.to_vec().unwrap();
        // The packet does carry the option, or the test would prove nothing.
        assert!(
            decode(&bytes)
                .edns
                .unwrap()
                .option(EdnsCode::Subnet)
                .is_some()
        );

        let options_of = |reply: &[u8]| decode(reply).edns.map(|edns| edns.options().options.len());
        let relayed = relayed(r.handle_upstream(&p, &bytes, Transport::Udp, at(1000)));
        assert_eq!(options_of(&relayed), Some(0));
        // Nor does the stored answer give one out.
        let cached = reply(r.handle_query(&unhex(Q_DIG), Transport::Udp, at(1001)));
        assert_eq!(options_of(&cached), Some(0));
    }

    /// A resolver with prefetch on and the captured answer `R_A` stored as the answer to
    /// `example.com` A at 1000, fresh for `lifetime` seconds.
    fn prefetching(lifetime: u32) -> Resolver {
        let mut r = resolver();
        r.set_prefetch(true);
        r.cache
            .insert(key("example.com", 1, false), unhex(R_A), lifetime, 1000);
        r
    }

    /// The prefetch that `action` asks for, after its checks: the client is answered now with
    /// `ttl` seconds left on every record, and nobody waits for the renewal. Panics for any other
    /// action.
    fn prefetch_of(action: Action, ttl: u32) -> Pending {
        let Action::ReplyAndRefresh(b, p) = action else {
            panic!("not a reply with a refresh: {action:?}")
        };
        assert_eq!(ttls(&b), [ttl, ttl]);
        assert!(p.is_prefetch() && p.is_refresh() && p.servfail().is_none());
        assert_eq!((p.name(), p.qtype()), ("example.com", 1));
        p
    }

    #[test]
    fn no_prefetch_while_off() {
        let mut r = resolver();
        r.cache
            .insert(key("example.com", 1, false), unhex(R_A), 300, 1000);
        for _ in 0..5 {
            assert_eq!(ttls(&reply(ask(&mut r, "example.com", 1, 1295))), [5, 5]);
        }
        // Turned off again after being on: no more than if it never was on.
        let mut r = prefetching(300);
        r.set_prefetch(false);
        for _ in 0..5 {
            assert_eq!(ttls(&reply(ask(&mut r, "example.com", 1, 1295))), [5, 5]);
        }
    }

    #[test]
    fn a_popular_entry_is_prefetched_once_inside_its_window() {
        let mut r = prefetching(300);
        assert_eq!(
            ttls(&reply(ask(&mut r, "example.com", 1, 1010))),
            [290, 290]
        );
        assert_eq!(
            ttls(&reply(ask(&mut r, "example.com", 1, 1020))),
            [280, 280]
        );
        // The third hit, with 29 seconds left of a window of 30.
        let p = prefetch_of(ask(&mut r, "example.com", 1, 1271), 29);
        // The upstream query is the client's, as any refresh's.
        assert_eq!(p.upstream_query(0xbeef)[..12], unhex(UPSTREAM_PLAIN)[..12]);
        // It stays a cache hit, counted as one.
        assert_eq!(r.stats().recent(1).next().unwrap().outcome, Outcome::Cached);
        // Once only: the next hits are plain replies.
        assert_eq!(ttls(&reply(ask(&mut r, "example.com", 1, 1275))), [25, 25]);
        assert_eq!(ttls(&reply(ask(&mut r, "example.com", 1, 1290))), [10, 10]);
        assert_eq!(
            r.stats().total(),
            Counts {
                queries: 5,
                cache_hits: 5,
                ..Counts::default()
            }
        );
    }

    #[test]
    fn no_prefetch_before_the_window() {
        let mut r = prefetching(300);
        // Three hits with 200 seconds left, and another well before the window.
        for mono in [1100, 1101, 1102, 1200] {
            assert_eq!(
                ttls(&reply(ask(&mut r, "example.com", 1, mono))),
                [300 - (mono - 1000) as u32; 2],
                "{mono}"
            );
        }
        // The window opens at 270 seconds of age; the hits so far still count.
        assert_eq!(ttls(&reply(ask(&mut r, "example.com", 1, 1269))), [31, 31]);
        prefetch_of(ask(&mut r, "example.com", 1, 1280), 20);
    }

    #[test]
    fn the_window_is_clamped() {
        // Lifetime, and the seconds of window it is to get.
        for (lifetime, window) in [(10_u32, 2_u32), (30, 3), (300, 30), (86_400, 60)] {
            let mut r = prefetching(lifetime);
            for _ in 0..3 {
                reply(ask(&mut r, "example.com", 1, 1000));
            }
            let before = 1000 + u64::from(lifetime - window - 1);
            assert!(
                matches!(ask(&mut r, "example.com", 1, before), Action::Reply(_)),
                "{lifetime}: one second before the window"
            );
            prefetch_of(ask(&mut r, "example.com", 1, before + 1), window);
        }
    }

    #[test]
    fn a_new_answer_rearms_the_prefetch() {
        let mut r = prefetching(300);
        for mono in [1010, 1020] {
            reply(ask(&mut r, "example.com", 1, mono));
        }
        let p = prefetch_of(ask(&mut r, "example.com", 1, 1271), 29);
        // The upstream answers: the entry is a new answer of 215 seconds, stored at 1272.
        assert_eq!(
            r.handle_upstream(&p, &unhex(R_A), Transport::Udp, at(1272)),
            UpstreamOutcome::Refreshed
        );
        // Hits count from 0 again: the first and second, inside the new window of 21 seconds,
        // are plain replies, and the third asks.
        assert_eq!(ttls(&reply(ask(&mut r, "example.com", 1, 1466))), [21, 21]);
        assert_eq!(ttls(&reply(ask(&mut r, "example.com", 1, 1467))), [20, 20]);
        let p = prefetch_of(ask(&mut r, "example.com", 1, 1468), 19);
        assert!(matches!(
            ask(&mut r, "example.com", 1, 1469),
            Action::Reply(_)
        ));
        // A refresh that failed does not store a new answer, and so asks for no second prefetch.
        let mut servfail = unhex(Q_PLAIN);
        servfail[2] = 0x81;
        servfail[3] = 0x82;
        assert_eq!(
            r.handle_upstream(&p, &servfail, Transport::Udp, at(1470)),
            UpstreamOutcome::Refreshed
        );
        assert!(matches!(
            ask(&mut r, "example.com", 1, 1471),
            Action::Reply(_)
        ));
    }

    #[test]
    fn the_prefetch_answer_is_refreshed_not_relayed() {
        let mut r = prefetching(300);
        for mono in [1010, 1020] {
            reply(ask(&mut r, "example.com", 1, mono));
        }
        let p = prefetch_of(ask(&mut r, "example.com", 1, 1280), 20);
        assert_eq!(
            r.handle_upstream(&p, &unhex(R_A), Transport::Udp, at(1281)),
            UpstreamOutcome::Refreshed
        );
        // And it was stored: the entry has its new lifetime, 215 seconds from 1281.
        assert_eq!(
            ttls(&reply(ask(&mut r, "example.com", 1, 1282))),
            [214, 214]
        );
        // A truncated answer over UDP is still to be asked for again over TCP.
        let mut tc = unhex(R_A);
        tc[2] |= 0x02;
        assert_eq!(
            r.handle_upstream(&p, &tc, Transport::Udp, at(1283)),
            UpstreamOutcome::RetryOverTcp
        );
        // Nothing was counted by any of it.
        assert_eq!(r.stats().total().queries, 4);
    }

    #[test]
    fn stale_hits_are_unchanged_by_prefetch() {
        let mut r = prefetching(215);
        // As in `a_stale_answer_is_served_and_a_refresh_asked_for`: a refresh, not a prefetch.
        let Action::ReplyAndRefresh(b, p) = ask(&mut r, "Example.com", 1, 1215) else {
            panic!("not a reply with a refresh")
        };
        assert_eq!(ttls(&b), [30, 30]);
        assert!(p.is_refresh() && !p.is_prefetch());
        assert_eq!(p.servfail(), None);
        assert_eq!(ttls(&reply(ask(&mut r, "example.com", 1, 1216))), [30, 30]);
        let Action::ReplyAndRefresh(_, p) = ask(&mut r, "example.com", 1, 1225) else {
            panic!("not a reply with a refresh")
        };
        assert!(!p.is_prefetch());
        assert_eq!(r.stats().recent(1).next().unwrap().outcome, Outcome::Stale);
        // And a plain stale refresh is the same with prefetch off.
        let mut r = resolver();
        store_a(&mut r, "example.com");
        let Action::ReplyAndRefresh(_, p) = ask(&mut r, "example.com", 1, 1215) else {
            panic!("not a reply with a refresh")
        };
        assert!(p.is_refresh() && !p.is_prefetch());
        // A forwarded question is neither.
        let p = forwarded(&mut r, &query(7, "example.org", 1), 1215);
        assert!(!p.is_refresh() && !p.is_prefetch());
    }

    #[test]
    fn suffix_rules_the_allow_list_and_case() {
        let mut r = resolver();
        assert!(is_blocked_reply(&reply(ask(
            &mut r,
            "a.b.tracker.example.net",
            1,
            1
        ))));
        assert!(is_blocked_reply(&reply(ask(
            &mut r,
            "ADS.Example.COM",
            1,
            1
        ))));
        assert!(matches!(
            ask(&mut r, "ok.tracker.example.net", 1, 1),
            Action::Forward(_)
        ));
        // An exact rule.
        assert!(matches!(
            ask(&mut r, "sub.ads.example.com", 1, 1),
            Action::Forward(_)
        ));
    }

    #[test]
    fn local_names_never_reach_upstream() {
        let mut r = resolver();
        assert_eq!(reply(ask(&mut r, "printer", 1, 1))[3] & 0x0f, 3);
        assert_eq!(
            reply(ask(&mut r, "1.0.168.192.in-addr.arpa", 12, 1))[3] & 0x0f,
            3
        );
        assert_eq!(
            r.stats().total(),
            Counts {
                queries: 2,
                blocked: 0,
                blocked_threat: 0,
                cache_hits: 0,
                forwarded: 0
            }
        );
        assert_eq!(r.stats().recent(1).next().unwrap().outcome, Outcome::Local);
    }

    // The "Single-label names" row: A and AAAA for a single-label name are answered here, every
    // other type goes through block, cache and forward like any name. `com. DS` and
    // `com. DNSKEY` are what a validating client asks first.
    #[test]
    fn a_single_label_name_goes_upstream_unless_an_address_is_asked_for() {
        let mut r = resolver();
        for qtype in [1, 28] {
            assert_eq!(reply(ask(&mut r, "printer", qtype, 1))[3] & 0x0f, 3);
        }
        assert_eq!(
            r.stats().total(),
            Counts {
                queries: 2,
                blocked: 0,
                blocked_threat: 0,
                cache_hits: 0,
                forwarded: 0
            }
        );
        for (name, qtype) in [
            ("com", 43),
            ("com", 48),
            ("example", 2),
            ("printer", 6),
            ("printer", 255),
            ("printer", 999),
        ] {
            let Action::Forward(p) = ask(&mut r, name, qtype, 2) else {
                panic!("{name} {qtype} is not forwarded")
            };
            assert_eq!((p.name(), p.qtype()), (name, qtype));
        }
        assert_eq!(r.stats().total().forwarded, 6);
        // The root is forwarded as before.
        assert!(matches!(ask(&mut r, ".", 2, 2), Action::Forward(_)));
    }

    // Through the cache: the answer to `com. DS` is stored and served like that of any name.
    #[test]
    fn the_answer_for_a_single_label_name_is_cached() {
        let mut r = resolver();
        let Action::Forward(p) = ask(&mut r, "com", 43, 1000) else {
            panic!("not forwarded")
        };
        let answer = answer_for(&p, 1).to_vec().unwrap();
        relayed(r.handle_upstream(&p, &answer, Transport::Udp, at(1000)));
        assert_eq!(r.cache_len(), 1);
        assert!(matches!(ask(&mut r, "com", 43, 1001), Action::Reply(_)));
        assert_eq!(r.stats().total().cache_hits, 1);
    }

    // Through the block check: a single-label name on the deny list is blocked for any type.
    #[test]
    fn a_denied_single_label_name_is_blocked_for_any_type() {
        let mut b = BlockSetBuilder::new();
        b.deny("tracker").unwrap();
        let mut r = Resolver::new(b.build());
        let reply = reply(ask(&mut r, "tracker", 43, 1));
        assert_eq!((reply[3] & 0x0f, decode(&reply).answers.len()), (0, 0));
        assert_eq!(r.stats().total().blocked, 1);
    }

    #[test]
    fn a_miss_is_forwarded() {
        let mut r = resolver();
        let Action::Forward(p) = ask(&mut r, "Example.COM", 28, 1) else {
            panic!()
        };
        assert_eq!(
            (p.name(), p.qtype(), p.is_refresh()),
            ("example.com", 28, false)
        );
        assert_eq!(p.upstream_query(0xbeef)[..2], [0xbe, 0xef]);
        let s = p.servfail().unwrap();
        assert_eq!((s[..2].to_vec(), s[3] & 0x0f), (vec![0, 7], 2));
        assert_eq!(r.stats().total().forwarded, 1);
    }

    #[test]
    fn malformed_packets_are_answered_or_dropped_and_not_counted() {
        let mut r = resolver();
        assert!(matches!(
            r.handle_query(&[1, 2, 3, 4, 5], Transport::Udp, at(1)),
            Action::Drop
        ));
        assert_eq!(
            reply(r.handle_query(&unhex("123401000001000000000000"), Transport::Udp, at(1))),
            unhex("123481810000000000000000")
        );
        assert_eq!(reply(ask(&mut r, "example.com", 252, 1))[3] & 0x0f, 5);
        assert_eq!(r.stats().total(), Counts::default());
        assert!(r.stats().recent(10).next().is_none());
    }

    #[test]
    fn a_pause_forwards_blocked_names_until_its_deadline() {
        let mut r = resolver();
        assert_eq!(r.paused_until(at(1000)), None);
        r.pause_until(1300);
        assert_eq!(r.paused_until(at(1299)), Some(1300));
        assert!(matches!(
            ask(&mut r, "ads.example.com", 1, 1299),
            Action::Forward(_)
        ));
        assert_eq!(
            r.stats().total(),
            Counts {
                queries: 1,
                blocked: 0,
                blocked_threat: 0,
                cache_hits: 0,
                forwarded: 1
            }
        );
        // Review Focus 4: the wall clock is not consulted.
        let stepped = Now {
            mono_secs: 1299,
            unix_secs: 4_000_000_000,
        };
        assert!(matches!(
            r.handle_query(&query(7, "ads.example.com", 1), Transport::Udp, stepped),
            Action::Forward(_)
        ));
        assert!(is_blocked_reply(&reply(ask(
            &mut r,
            "ads.example.com",
            1,
            1300
        ))));
        assert_eq!(r.paused_until(at(1300)), None);
        r.pause_until(9999);
        r.resume();
        assert!(is_blocked_reply(&reply(ask(
            &mut r,
            "ads.example.com",
            1,
            1301
        ))));
    }

    #[test]
    fn lists_says_what_the_block_set_blocks_whatever_the_pause() {
        let mut r = resolver();
        let listed = |r: &Resolver| {
            [
                "ads.example.com",
                "ADS.Example.COM.",
                "a.b.tracker.example.net",
            ]
            .map(|name| r.lists(name))
        };
        let not_listed = |r: &Resolver| {
            [
                "example.com",
                // An exact rule covers no subdomain.
                "sub.ads.example.com",
                // The allow rule beats the suffix rule, for the name and for what is under it.
                "ok.tracker.example.net",
                "deeper.ok.tracker.example.net",
                // An escaped dot is no label separator, so no parent of it is listed.
                "x\\.tracker.example.net",
                "",
                ".",
            ]
            .map(|name| r.lists(name))
        };
        assert_eq!(listed(&r), [true; 3]);
        assert_eq!(not_listed(&r), [false; 7]);

        // A pause forwards the name, and the lists still hold it.
        r.pause_until(1300);
        assert!(r.paused_until(at(10)).is_some());
        assert!(matches!(
            ask(&mut r, "ads.example.com", 1, 10),
            Action::Forward(_)
        ));
        assert_eq!(listed(&r), [true; 3]);
        assert_eq!(not_listed(&r), [false; 7]);

        // A name over 253 bytes is no name, though a parent of it is listed.
        let label = "a".repeat(63);
        assert!(r.lists(&format!("{label}.tracker.example.net")));
        assert!(!r.lists(&format!(
            "{label}.{label}.{label}.{label}.tracker.example.net"
        )));
        // Nothing was counted by asking.
        assert_eq!(r.stats().total().queries, 1);
    }

    #[test]
    fn swapping_the_block_set_takes_effect_on_the_next_query() {
        let mut r = resolver();
        r.set_blockset(BlockSet::default());
        assert!(matches!(
            ask(&mut r, "ads.example.com", 1, 1),
            Action::Forward(_)
        ));
        let mut b = BlockSetBuilder::new();
        b.deny("example.org").unwrap();
        r.set_blockset(b.build());
        assert!(is_blocked_reply(&reply(ask(
            &mut r,
            "www.example.org",
            1,
            2
        ))));
    }

    #[test]
    fn replacing_the_block_set_hands_back_the_old_one() {
        // The caller frees the old set where it likes (off the thread that holds the lock): it is
        // the whole old set, which still blocks what it blocked, and the new one is in force.
        let mut r = resolver();
        let mut b = BlockSetBuilder::new();
        b.deny("example.org").unwrap();
        let old = r.replace_blockset(b.build());
        assert!(old.is_blocked("ads.example.com"));
        assert!(!old.is_blocked("www.example.org"));
        assert!(is_blocked_reply(&reply(ask(
            &mut r,
            "www.example.org",
            1,
            3
        ))));
        assert!(matches!(
            ask(&mut r, "ads.example.com", 1, 4),
            Action::Forward(_)
        ));
        // And what comes back next is the set that went in.
        let back = r.replace_blockset(BlockSet::default());
        assert!(back.is_blocked("www.example.org") && !back.is_blocked("ads.example.com"));
    }

    // The wall clock stepping back, to before the pause was set, does not end the pause either.
    #[test]
    fn a_pause_ignores_the_wall_clock_in_both_directions() {
        let mut r = resolver();
        r.pause_until(1300);
        for unix_secs in [0, 1300, 1_800_000_000, u64::MAX] {
            let before = Now {
                mono_secs: 1299,
                unix_secs,
            };
            assert_eq!(r.paused_until(before), Some(1300), "{unix_secs}");
            assert!(matches!(
                r.handle_query(&query(7, "ads.example.com", 1), Transport::Udp, before),
                Action::Forward(_)
            ));
            let reached = Now {
                mono_secs: 1300,
                unix_secs,
            };
            assert_eq!(r.paused_until(reached), None, "{unix_secs}");
            assert!(is_blocked_reply(&reply(r.handle_query(
                &query(7, "ads.example.com", 1),
                Transport::Udp,
                reached
            ))));
        }
    }

    #[test]
    fn a_fresh_cached_answer_is_served_with_the_lifetime_left() {
        let mut r = resolver();
        store_a(&mut r, "example.com");
        // Another ID than the stored answer's, and another spelling of the name.
        let mut asked = unhex(Q_MIXED);
        asked[..2].copy_from_slice(&[0xab, 0xcd]);
        let b = reply(r.handle_query(&asked, Transport::Udp, at(1100)));
        assert_eq!(b[..2], [0xab, 0xcd]);
        assert_eq!(b[12..29], asked[12..]);
        assert_eq!(decode(&b).answers.len(), 2);
        assert_eq!(ttls(&b), [115, 115]);
        // The last second of its lifetime.
        assert_eq!(ttls(&reply(ask(&mut r, "example.com", 1, 1214))), [1, 1]);
        assert_eq!(
            r.stats().total(),
            Counts {
                queries: 2,
                blocked: 0,
                blocked_threat: 0,
                cache_hits: 2,
                forwarded: 0
            }
        );
        let entry = r.stats().recent(1).next().unwrap();
        assert_eq!(
            (&*entry.name, entry.qtype, entry.outcome),
            ("example.com", 1, Outcome::Cached)
        );
        assert_eq!(r.cache_len(), 1);
    }

    #[test]
    fn a_stale_answer_is_served_and_a_refresh_asked_for() {
        let mut r = resolver();
        store_a(&mut r, "example.com");
        let Action::ReplyAndRefresh(b, p) = ask(&mut r, "Example.com", 1, 1215) else {
            panic!("not a reply with a refresh")
        };
        assert_eq!(b[..2], [0, 7]);
        assert_eq!(ttls(&b), [30, 30]);
        assert_eq!(
            (p.name(), p.qtype(), p.is_refresh()),
            ("example.com", 1, true)
        );
        // Nobody waits for a refresh, so there is nobody to tell that it failed.
        assert_eq!(p.servfail(), None);
        let upstream = p.upstream_query(0xbeef);
        assert_eq!(upstream[..12], unhex(UPSTREAM_PLAIN)[..12]);
        // The asking client's spelling.
        assert_eq!(upstream[12..25], query(7, "Example.com", 1)[12..25]);
        assert_eq!(upstream[25..], unhex(UPSTREAM_PLAIN)[25..]);

        // Asked again within 10 seconds: served, with no second refresh.
        assert_eq!(ttls(&reply(ask(&mut r, "example.com", 1, 1216))), [30, 30]);
        assert_eq!(
            r.stats().total(),
            Counts {
                queries: 2,
                blocked: 0,
                blocked_threat: 0,
                cache_hits: 2,
                forwarded: 0
            }
        );
        assert_eq!(r.stats().recent(1).next().unwrap().outcome, Outcome::Stale);
        assert!(matches!(
            ask(&mut r, "example.com", 1, 1225),
            Action::ReplyAndRefresh(..)
        ));

        // An hour past its lifetime it is gone.
        assert!(matches!(
            ask(&mut r, "example.com", 1, 4815),
            Action::Forward(_)
        ));
        assert_eq!(r.cache_len(), 0);
        assert_eq!(r.stats().total().forwarded, 1);
    }

    #[test]
    fn a_cached_body_that_does_not_decode_is_a_miss() {
        let mut r = resolver();
        r.cache
            .insert(key("example.com", 1, false), vec![0xff; 5], 215, 1000);
        // Fresh, then stale.
        for mono in [1001, 1215] {
            let Action::Forward(p) = ask(&mut r, "example.com", 1, mono) else {
                panic!("not forwarded at {mono}")
            };
            assert!(!p.is_refresh() && p.servfail().is_some());
        }
        assert_eq!(
            r.stats().total(),
            Counts {
                queries: 2,
                blocked: 0,
                blocked_threat: 0,
                cache_hits: 0,
                forwarded: 2
            }
        );
    }

    // Review Focus 5, from the client side: an answer stored while blocking was paused.
    #[test]
    fn a_blocked_name_is_never_answered_from_the_cache() {
        let mut r = resolver();
        store_a(&mut r, "ads.example.com");
        assert!(is_blocked_reply(&reply(ask(
            &mut r,
            "ads.example.com",
            1,
            1100
        ))));
        r.pause_until(1200);
        assert_eq!(
            ttls(&reply(ask(&mut r, "ads.example.com", 1, 1150))),
            [65, 65]
        );
        // The pause is over and the entry has 15 seconds left: blocked all the same.
        assert!(is_blocked_reply(&reply(ask(
            &mut r,
            "ads.example.com",
            1,
            1200
        ))));
        assert_eq!(
            r.stats().total(),
            Counts {
                queries: 3,
                blocked: 2,
                blocked_threat: 0,
                cache_hits: 1,
                forwarded: 0
            }
        );

        // A blocked query does not touch the cache. The entry is stale from 1215, and the query
        // blocked then did not use up its refresh: the next one let through still asks for it.
        assert!(is_blocked_reply(&reply(ask(
            &mut r,
            "ads.example.com",
            1,
            1215
        ))));
        r.pause_until(1300);
        assert!(matches!(
            ask(&mut r, "ads.example.com", 1, 1215),
            Action::ReplyAndRefresh(..)
        ));
        assert!(is_blocked_reply(&reply(ask(
            &mut r,
            "ads.example.com",
            1,
            1300
        ))));
    }

    #[test]
    fn an_answer_is_served_only_for_its_own_name_type_and_do_bit() {
        let mut r = resolver();
        store_a(&mut r, "example.com");
        store_a(&mut r, "a.b.example.com");
        let is_forwarded = |r: &mut Resolver, packet: &[u8]| {
            matches!(
                r.handle_query(packet, Transport::Udp, at(1001)),
                Action::Forward(_)
            )
        };
        assert!(is_forwarded(&mut r, &query(7, "example.com", 28)));
        assert!(is_forwarded(&mut r, &query(7, "www.example.com", 1)));
        assert!(is_forwarded(&mut r, &unhex(Q_DO)));
        // Review Focus 2: the first label is the 3 bytes `a.b`, not the labels `a` and `b`.
        assert!(is_forwarded(&mut r, &unhex(Q_DOTTED)));
        assert_eq!(
            ttls(&reply(ask(&mut r, "a.b.example.com", 1, 1001))),
            [214, 214]
        );

        // An answer stored for a query with the DO bit is not one for a query without it.
        r.cache
            .insert(key("example.net", 1, true), unhex(R_A), 215, 1000);
        assert!(is_forwarded(&mut r, &query(7, "example.net", 1)));

        // An OPT record without the DO bit asks for the same answer as no OPT record, and the
        // reply carries the asking client's ID and an OPT record of its own.
        let b = reply(r.handle_query(&unhex(Q_DIG), Transport::Udp, at(1001)));
        assert_eq!(b[..2], [0xab, 0xcd]);
        assert_eq!(ttls(&b), [214, 214]);
        assert!(b.ends_with(&unhex("00 0029 04d0 00000000 0000")));
        // A client that sent no OPT record gets none: no additional record at all.
        let plain = reply(r.handle_query(&unhex(Q_PLAIN), Transport::Udp, at(1001)));
        assert_eq!(
            (b[10..12].to_vec(), plain[10..12].to_vec()),
            ([0, 1].to_vec(), [0, 0].to_vec())
        );
    }

    #[test]
    fn the_transport_decides_the_size_limit_of_a_cached_reply() {
        let mut r = resolver();
        // 40 A records come to 669 bytes: over the 512 of a UDP reply to a query without OPT.
        let mut big = decode(&unhex(R_A));
        let record = big.answers[0].clone();
        big.answers = vec![record; 40];
        r.cache.insert(
            key("example.com", 1, false),
            big.to_vec().unwrap(),
            215,
            1000,
        );
        let udp = reply(r.handle_query(&unhex(Q_PLAIN), Transport::Udp, at(1001)));
        assert!(udp[2] & 0x02 != 0 && udp.len() == 29);
        let tcp = reply(r.handle_query(&unhex(Q_PLAIN), Transport::Tcp, at(1001)));
        assert!(tcp[2] & 0x02 == 0 && tcp.len() == 669);
        assert_eq!(decode(&tcp).answers.len(), 40);
    }

    #[test]
    fn a_refused_question_is_neither_blocked_nor_cached_nor_counted() {
        let mut r = resolver();
        store_a(&mut r, "example.com");
        // Class CHAOS: a blocked name, a cached one, a local one.
        for name in ["ads.example.com", "example.com", "printer"] {
            let mut chaos = query(7, name, 1);
            let n = chaos.len();
            chaos[n - 1] = 3;
            let b = reply(r.handle_query(&chaos, Transport::Udp, at(1001)));
            assert_eq!(b[3] & 0x0f, 5, "{name}");
            assert_eq!(b[6..8], [0, 0], "{name}");
        }
        // EDNS version 1: BADVERS, whose high bits are in the OPT record.
        let mut v1 = unhex(Q_AAAA_EDNS);
        let n = v1.len();
        v1[n - 5] = 1;
        let b = reply(r.handle_query(&v1, Transport::Udp, at(1001)));
        assert_eq!(b[3] & 0x0f, 0);
        assert!(b.ends_with(&unhex("00 0029 04d0 01000000 0000")));

        assert_eq!(r.stats().total(), Counts::default());
        assert!(r.stats().recent(10).next().is_none());
        assert_eq!(r.stats().last_blocked(at(1001)), None);
    }

    #[test]
    fn memory_is_bounded_by_the_three_capacities() {
        let mut r = resolver();
        for i in 0..=CACHE_CAPACITY {
            let name = format!("n{i}.example.com");
            r.cache.insert(key(&name, 1, false), vec![0], 60, 0);
        }
        assert_eq!(r.cache_len(), 10_000);

        // 1,024 names blocked after it push a name out of the 24-hour counts: blocked again, it
        // starts from 1.
        assert!(is_blocked_reply(&reply(ask(
            &mut r,
            "tracker.example.net",
            1,
            1
        ))));
        for i in 0..BLOCKED_NAMES_TRACKED {
            let name = format!("n{i}.tracker.example.net");
            assert!(is_blocked_reply(&reply(ask(&mut r, &name, 1, 1))));
        }
        let count_of_last = |r: &Resolver| r.stats().last_blocked(at(1)).unwrap().count_24h;
        assert_eq!(count_of_last(&r), 1);
        ask(&mut r, "n0.tracker.example.net", 1, 1);
        assert_eq!(count_of_last(&r), 2);
        ask(&mut r, "tracker.example.net", 1, 1);
        assert_eq!(count_of_last(&r), 1);

        for _ in 0..QUERY_LOG_CAPACITY {
            ask(&mut r, "example.com", 1, 1);
        }
        assert_eq!(r.stats().recent(usize::MAX).count(), 50_000);
        assert!(
            r.stats()
                .recent(usize::MAX)
                .all(|entry| entry.outcome == Outcome::Forwarded)
        );
        assert_eq!(r.stats().total().queries, 1_027 + 50_000);
    }

    // `at(0)` is 08:00 UTC. One hour east of UTC the local day ends at 54,000 seconds, one hour
    // before the UTC day does.
    #[test]
    fn the_utc_offset_places_the_midnight_of_today() {
        let mut r = resolver();
        r.set_utc_offset(3600);
        ask(&mut r, "example.com", 1, 53_000);
        assert_eq!(r.stats().today(at(53_999)).queries, 1);
        assert_eq!(r.stats().today(at(54_000)), Counts::default());
        assert_eq!(r.stats().total().queries, 1);
    }

    #[test]
    fn a_relayed_answer_is_the_real_resolvers_bytes() {
        let mut r = resolver();
        // Asserts that the reply equals the capture, byte for byte.
        cached_example(&mut r);
        assert_eq!(r.cache_len(), 1);
        let p = forwarded(&mut r, &unhex(Q_NODATA), 1000);
        assert_eq!(
            r.handle_upstream(&p, &unhex(R_NODATA), Transport::Udp, at(1000)),
            UpstreamOutcome::Reply(unhex(R_NODATA))
        );
    }

    #[test]
    fn a_cache_hit_carries_the_clients_id_and_spelling() {
        let mut r = resolver();
        cached_example(&mut r);
        let q = query(0x9999, "EXAMPLE.com", 1);
        let b = reply(r.handle_query(&q, Transport::Udp, at(1100)));
        assert_eq!((&b[..2], &b[12..29]), (&[0x99, 0x99][..], &q[12..29]));
        assert_eq!(ttls(&b), [115, 115]);
        let data = |bytes: &[u8]| {
            decode(bytes)
                .answers
                .iter()
                .map(|a| a.data.to_string())
                .collect::<Vec<_>>()
        };
        assert_eq!(data(&b), data(&unhex(R_A)));
        assert_eq!(
            r.stats().total(),
            Counts {
                queries: 2,
                blocked: 0,
                blocked_threat: 0,
                cache_hits: 1,
                forwarded: 1
            }
        );
    }

    #[test]
    fn a_stale_answer_asks_for_one_refresh() {
        let mut r = resolver();
        cached_example(&mut r);
        let Action::ReplyAndRefresh(b, p) = ask(&mut r, "example.com", 1, 1215) else {
            panic!("not a reply with a refresh")
        };
        assert_eq!(ttls(&b), [30, 30]);
        assert!(p.is_refresh() && p.servfail().is_none());
        // No second refresh yet.
        assert_eq!(ttls(&reply(ask(&mut r, "example.com", 1, 1216))), [30, 30]);
        // The first one never came back.
        assert!(matches!(
            ask(&mut r, "example.com", 1, 1225),
            Action::ReplyAndRefresh(..)
        ));
        assert_eq!(
            r.handle_upstream(&p, &unhex(R_A), Transport::Udp, at(1226)),
            UpstreamOutcome::Refreshed
        );
        assert_eq!(
            ttls(&reply(ask(&mut r, "example.com", 1, 1227))),
            [214, 214]
        );
        assert_eq!(r.stats().recent(1).next().unwrap().outcome, Outcome::Cached);
        assert_eq!(r.stats().total().cache_hits, 4);
    }

    #[test]
    fn an_answer_stale_for_an_hour_is_forwarded() {
        let mut r = resolver();
        cached_example(&mut r);
        assert!(matches!(
            ask(&mut r, "example.com", 1, 1215 + 3599),
            Action::ReplyAndRefresh(..)
        ));
        assert!(matches!(
            ask(&mut r, "example.com", 1, 1215 + 3600),
            Action::Forward(_)
        ));
    }

    #[test]
    fn a_truncated_upstream_answer_asks_for_tcp() {
        let mut r = resolver();
        let p = forwarded(&mut r, &unhex(Q_PLAIN), 1000);
        let mut tc = unhex(R_A);
        tc[2] |= 0x02;
        assert_eq!(
            r.handle_upstream(&p, &tc, Transport::Udp, at(1000)),
            UpstreamOutcome::RetryOverTcp
        );
        assert!(matches!(
            r.handle_upstream(&p, &tc, Transport::Tcp, at(1000)),
            UpstreamOutcome::Reply(_)
        ));
        assert_eq!(r.cache_len(), 0);
    }

    // Review Focus 3.
    #[test]
    fn answers_to_other_questions_change_nothing() {
        let mut r = resolver();
        let p = forwarded(&mut r, &unhex(Q_PLAIN), 1000);
        let aaaa = forwarded(&mut r, &query(1, "example.com", 28), 1000);
        for packet in [
            unhex(R_NODATA),
            unhex(R_NXDOMAIN),
            unhex(Q_PLAIN),
            vec![],
            vec![0xff; 40],
        ] {
            assert_eq!(
                r.handle_upstream(&p, &packet, Transport::Udp, at(1001)),
                UpstreamOutcome::Mismatch
            );
        }
        assert_eq!(
            r.handle_upstream(&aaaa, &unhex(R_A), Transport::Udp, at(1001)),
            UpstreamOutcome::Mismatch
        );
        assert_eq!(r.cache_len(), 0);
        assert!(matches!(
            ask(&mut r, "example.com", 1, 1002),
            Action::Forward(_)
        ));
    }

    // Review Focus 3 on a cache that holds the answer: each packet is well formed and close to
    // the answer waited for, and none may be taken for it.
    #[test]
    fn a_mismatch_leaves_the_stored_answer_and_the_counters_as_they_were() {
        let mut r = resolver();
        cached_example(&mut r);
        let Action::ReplyAndRefresh(_, refresh) = ask(&mut r, "example.com", 1, 1215) else {
            panic!("not a reply with a refresh")
        };
        let waiting = forwarded(&mut r, &query(7, "a.b.example.com", 1), 1215);
        let dotted = forwarded(&mut r, &unhex(Q_DOTTED), 1215);
        let counted = r.stats().total();

        let answer = decode(&unhex(R_A));
        let asking = |questions: &[Vec<u8>]| {
            let mut packet = answer.clone();
            packet.queries.clear();
            for question in questions {
                packet.queries.extend(decode(question).queries);
            }
            packet.to_vec().unwrap()
        };
        // The right question and the records, but a query.
        let mut not_a_response = unhex(R_A);
        not_a_response[2] &= 0x7f;
        // Class CHAOS.
        let mut other_class = unhex(R_A);
        other_class[28] = 3;
        // The right question and the records, but the opcode of a STATUS or a NOTIFY, not of a
        // query.
        let [mut status, mut notify] = [unhex(R_A), unhex(R_A)];
        status[2] |= 0x10;
        notify[2] |= 0x20;
        // Truncated, which does not make another question's answer one to ask for again.
        let mut other_cut_short = asking(&[query(0, "example.net", 1)]);
        other_cut_short[2] |= 0x02;
        let others = [
            asking(&[query(0, "example.net", 1)]),
            asking(&[query(0, "www.example.com", 1)]),
            asking(&[query(0, "com", 1)]),
            asking(&[query(0, "example.com", 28)]),
            asking(&[]),
            asking(&[unhex(Q_PLAIN), unhex(Q_PLAIN)]),
            asking(&[unhex(Q_PLAIN), query(0, "a.b.example.com", 1)]),
            not_a_response,
            other_class,
            status,
            notify,
            other_cut_short,
        ];
        for (i, packet) in others.iter().enumerate() {
            for p in [&refresh, &waiting, &dotted] {
                for via in [Transport::Udp, Transport::Tcp] {
                    assert_eq!(
                        r.handle_upstream(p, packet, via, at(1216)),
                        UpstreamOutcome::Mismatch,
                        "packet {i} for {:?} over {via:?}",
                        p.name()
                    );
                }
            }
        }
        // Review Focus 2: the labels `a` and `b` are not the label `a.b`, in either direction.
        let two_labels = answer_for(&waiting, 1).to_vec().unwrap();
        let one_label = answer_for(&dotted, 1).to_vec().unwrap();
        assert_eq!(
            r.handle_upstream(&dotted, &two_labels, Transport::Udp, at(1216)),
            UpstreamOutcome::Mismatch
        );
        assert_eq!(
            r.handle_upstream(&waiting, &one_label, Transport::Udp, at(1216)),
            UpstreamOutcome::Mismatch
        );

        assert_eq!(r.stats().total(), counted);
        assert_eq!(r.stats().recent(usize::MAX).count(), 4);
        assert_eq!(r.cache_len(), 1);
        // The stored answer is still the stale one, and its refresh is still under way.
        assert_eq!(ttls(&reply(ask(&mut r, "example.com", 1, 1216))), [30, 30]);
        assert!(matches!(
            ask(&mut r, "a.b.example.com", 1, 1216),
            Action::Forward(_)
        ));

        // Each question still takes its own answer.
        assert_eq!(
            r.handle_upstream(&refresh, &unhex(R_A), Transport::Udp, at(1217)),
            UpstreamOutcome::Refreshed
        );
        relayed(r.handle_upstream(&waiting, &two_labels, Transport::Udp, at(1217)));
        relayed(r.handle_upstream(&dotted, &one_label, Transport::Udp, at(1217)));
        assert_eq!(r.cache_len(), 3);
        assert_eq!(r.stats().total().queries, counted.queries + 2);
    }

    #[test]
    fn the_waiting_client_gets_its_own_id_and_spelling_whatever_the_upstream_echoed() {
        let mut r = resolver();
        let q = query(0x9999, "EXAMPLE.com", 1);
        let p = forwarded(&mut r, &q, 1000);
        let mut upstream = decode(&unhex(R_A));
        upstream.metadata.id = 0xbeef;
        upstream.queries = decode(&query(0, "eXaMpLe.CoM", 1)).queries;
        let packet = upstream.to_vec().unwrap();
        let b = relayed(r.handle_upstream(&p, &packet, Transport::Udp, at(1000)));
        assert_eq!((&b[..2], &b[12..29]), (&[0x99, 0x99][..], &q[12..29]));
        assert_eq!(decode(&b).answers, upstream.answers);
        // Stored under the name in lower case, so every spelling finds it.
        let hit = reply(ask(&mut r, "example.COM", 1, 1001));
        assert_eq!(hit[12..29], query(7, "example.COM", 1)[12..29]);
        assert_eq!(ttls(&hit), [214, 214]);
    }

    #[test]
    fn an_answer_is_stored_under_the_pending_questions_key_and_without_the_opt() {
        let mut r = resolver();
        let p = forwarded(&mut r, &unhex(Q_DO), 1000);
        // The upstream's own OPT record: another size, and the DO bit clear.
        let mut upstream = answer_for(&p, 0xbeef);
        let mut edns = Edns::new();
        edns.set_max_payload(4096).set_dnssec_ok(false);
        upstream.set_edns(edns);
        let packet = upstream.to_vec().unwrap();
        assert!(packet.ends_with(&unhex("00 0029 1000 00000000 0000")));

        let b = relayed(r.handle_upstream(&p, &packet, Transport::Udp, at(1000)));
        // The client's OPT record comes back, not the upstream's.
        assert!(b.ends_with(&unhex("00 0029 04d0 00008000 0000")));

        // The DO bit of the key is the question's, whatever the upstream's OPT record says.
        assert_eq!(r.cache_len(), 1);
        assert!(r.cache.get(&key("example.com", 1, false), 1000).is_none());
        let Some(Hit::Fresh { body, ttl: 215, .. }) =
            r.cache.get(&key("example.com", 1, true), 1000)
        else {
            panic!("not stored under the question's key")
        };
        let stored = decode(body);
        assert!(stored.edns.is_none() && stored.additionals.is_empty());
        assert_eq!(body[10..12], [0, 0]);
        assert_eq!(stored.answers, upstream.answers);
    }

    // 15 TXT records of 255 bytes of text and one of `text` bytes come to 4,062 + `text` bytes:
    // the most the cache takes, then one byte more.
    #[test]
    fn an_answer_too_long_to_store_keeps_its_own_ttls() {
        for (text, stored) in [(34, true), (35, false)] {
            let mut r = resolver();
            let Action::Forward(p) = r.handle_query(&unhex(Q_PLAIN), Transport::Tcp, at(1000))
            else {
                panic!("not forwarded")
            };
            let mut upstream = decode(&unhex(R_A));
            let name = upstream.answers[0].name.clone();
            let txt = |len: usize| RData::TXT(TXT::from_bytes(vec![&[b'x'; 255][..len]]));
            upstream.answers = vec![Record::from_rdata(name.clone(), 600, txt(255)); 15];
            upstream
                .answers
                .push(Record::from_rdata(name, 60, txt(text)));
            let packet = upstream.to_vec().unwrap();
            assert_eq!(packet.len(), 4062 + text);

            let b = relayed(r.handle_upstream(&p, &packet, Transport::Tcp, at(1000)));
            let mut expected = vec![if stored { 60 } else { 600 }; 15];
            expected.push(60);
            assert_eq!(ttls(&b), expected, "{text} bytes of text");
            assert_eq!(r.cache_len(), usize::from(stored), "{text} bytes of text");
        }
    }

    #[test]
    fn negative_answers_are_relayed_and_cached() {
        let mut r = resolver();
        let p = forwarded(&mut r, &unhex(Q_NODATA), 1000);
        r.handle_upstream(&p, &unhex(R_NODATA), Transport::Udp, at(1000));
        let b = reply(r.handle_query(&unhex(Q_NODATA), Transport::Udp, at(1010)));
        assert_eq!(
            (b[3] & 0x0f, decode(&b).answers.len(), ttls(&b)),
            (0, 0, vec![1790])
        );
        let p = forwarded(&mut r, &query(0x5678, "host.invalid", 1), 1000);
        let b = relayed(r.handle_upstream(&p, &unhex(R_NXDOMAIN), Transport::Udp, at(1000)));
        // NXDOMAIN, AA cleared, and the ceiling of a negative lifetime.
        assert_eq!((b[3] & 0x0f, b[2] & 0x04, ttls(&b)), (3, 0, vec![3600]));
        assert_eq!(reply(ask(&mut r, "host.invalid", 1, 4599))[3] & 0x0f, 3);
    }

    #[test]
    fn uncacheable_answers_are_relayed_as_they_are() {
        let mut r = resolver();
        let p = forwarded(&mut r, &unhex(Q_PLAIN), 1000);
        let mut servfail = unhex(Q_PLAIN);
        servfail[2] = 0x81;
        servfail[3] = 0x82;
        assert_eq!(
            r.handle_upstream(&p, &servfail, Transport::Udp, at(1000)),
            UpstreamOutcome::Reply(servfail.clone())
        );
        assert_eq!(r.cache_len(), 0);
    }

    // The high bits of such an rcode are in the upstream's OPT record. Removing that record must
    // not leave the low bits to be read alone: here they are 0, which is success.
    #[test]
    fn an_upstream_rcode_above_15_is_servfail_and_is_not_stored() {
        let mut r = resolver();
        let p = forwarded(&mut r, &unhex(Q_PLAIN), 1000);
        let mut upstream = answer_for(&p, 1);
        upstream.metadata.response_code = ResponseCode::BADVERS;
        let packet = upstream.to_vec().unwrap();
        assert_eq!(packet[3] & 0x0f, 0);
        assert!(packet.ends_with(&unhex("00 0029 04d0 01000000 0000")));
        assert_eq!(
            r.handle_upstream(&p, &packet, Transport::Udp, at(1000)),
            UpstreamOutcome::Reply(p.servfail().unwrap())
        );
        assert_eq!(r.cache_len(), 0);
    }

    // The upstream failed, or did not finish: nothing in the packet says the stored answer is
    // wrong, and a stale one is what serve-stale is for.
    #[test]
    fn a_refresh_that_failed_leaves_the_stale_answer() {
        let mut r = resolver();
        let p = stale_refresh(&mut r);
        let mut tc = unhex(R_A);
        tc[2] |= 0x02;
        assert_eq!(
            r.handle_upstream(&p, &tc, Transport::Udp, at(1216)),
            UpstreamOutcome::RetryOverTcp
        );
        let failing = |rcode| {
            let mut answer = answer_for(&p, 1);
            answer.metadata.response_code = rcode;
            answer.to_vec().unwrap()
        };
        let mut servfail = unhex(Q_PLAIN);
        servfail[2] = 0x81;
        servfail[3] = 0x82;
        for (what, packet) in [
            ("truncated", tc),
            ("SERVFAIL", servfail),
            ("SERVFAIL with answers", failing(ResponseCode::ServFail)),
            ("REFUSED", failing(ResponseCode::Refused)),
            ("NOTIMP", failing(ResponseCode::NotImp)),
            ("FORMERR", failing(ResponseCode::FormErr)),
            ("NOTAUTH", failing(ResponseCode::NotAuth)),
        ] {
            assert_eq!(
                r.handle_upstream(&p, &packet, Transport::Tcp, at(1216)),
                UpstreamOutcome::Refreshed,
                "{what}"
            );
            // Still stale: a fresh answer would carry 214.
            assert_eq!(
                ttls(&reply(ask(&mut r, "example.com", 1, 1217))),
                [30, 30],
                "{what}"
            );
            assert_eq!(r.cache_len(), 1, "{what}");
        }
    }

    // The upstream answered, and what it answered is not what is stored: the stored answer is
    // known to be out of date, and serving it for another hour would be wrong.
    #[test]
    fn a_definitive_answer_that_cannot_be_stored_removes_the_stale_one() {
        for what in [
            "too long",
            "NXDOMAIN without an SOA",
            "no data without an SOA",
        ] {
            let mut r = resolver();
            let p = stale_refresh(&mut r);
            let mut upstream = answer_for(&p, 1);
            match what {
                "too long" => {
                    // 15 TXT records of 255 bytes of text and one of 35 come to 4,097 bytes, one
                    // over what the cache takes.
                    let name = upstream.answers[0].name.clone();
                    let txt = |len: usize| RData::TXT(TXT::from_bytes(vec![&[b'x'; 255][..len]]));
                    upstream.answers = vec![Record::from_rdata(name.clone(), 600, txt(255)); 15];
                    upstream.answers.push(Record::from_rdata(name, 60, txt(35)));
                }
                "NXDOMAIN without an SOA" => {
                    upstream.answers.clear();
                    upstream.metadata.response_code = ResponseCode::NXDomain;
                }
                _ => upstream.answers.clear(),
            }
            let packet = upstream.to_vec().unwrap();
            assert_eq!(
                r.handle_upstream(&p, &packet, Transport::Tcp, at(1216)),
                UpstreamOutcome::Refreshed,
                "{what}"
            );
            assert_eq!(r.cache_len(), 0, "{what}");
            assert!(
                matches!(ask(&mut r, "example.com", 1, 1217), Action::Forward(_)),
                "{what}: still served from the cache"
            );
        }
    }

    #[test]
    fn dnssec_ok_queries_do_not_share_entries() {
        let mut r = resolver();
        cached_example(&mut r);
        assert!(matches!(
            r.handle_query(&unhex(Q_DO), Transport::Udp, at(1001)),
            Action::Forward(_)
        ));
        assert!(matches!(
            r.handle_query(&unhex(Q_PLAIN), Transport::Udp, at(1001)),
            Action::Reply(_)
        ));
    }

    // Review Focus 5.
    #[test]
    fn the_end_of_a_pause_blocks_a_name_cached_during_it() {
        let mut b = BlockSetBuilder::new();
        b.deny("example.com").unwrap();
        let mut r = Resolver::new(b.build());
        r.pause_until(1100);
        cached_example(&mut r);
        assert_eq!(
            ttls(&reply(ask(&mut r, "example.com", 1, 1099))),
            [116, 116]
        );
        assert!(is_blocked_reply(&reply(ask(
            &mut r,
            "example.com",
            1,
            1100
        ))));
    }

    #[test]
    fn entry_points_never_panic_and_stay_bounded() {
        entry_points_on_arbitrary_packets(false);
    }

    #[test]
    fn entry_points_never_panic_and_stay_bounded_with_prefetch_on() {
        entry_points_on_arbitrary_packets(true);
    }

    // Both entry points on arbitrary packets, with each question that goes upstream kept until
    // it is answered. A round's upstream packet is as often one made for the question it is
    // given to as one of the captured answers, so that the cache fills past its capacity.
    // `prefetch` is the resolver's switch of that name.
    fn entry_points_on_arbitrary_packets(prefetch: bool) {
        /// The most questions kept waiting; past it the oldest gives up, as after a timeout.
        const WAITING: usize = 64;
        let queries = [Q_PLAIN, Q_MIXED, Q_DIG, Q_AAAA_EDNS, Q_DO, Q_NODATA].map(unhex);
        let answers = [R_A, R_NODATA, R_NXDOMAIN].map(unhex);
        let mut rng = Rng::new(11);
        let mut r = resolver();
        r.set_prefetch(prefetch);
        let mut waiting: Vec<Pending> = Vec::new();
        // What handle_query asked for, then what handle_upstream did.
        let (mut replies, mut forwards, mut refreshes, mut drops) = (0, 0, 0, 0);
        let mut prefetches = 0;
        let (mut relays, mut refreshed, mut retries, mut mismatches) = (0, 0, 0, 0);
        let mut fullest = 0;

        for i in 0..200_000_usize {
            // Seven rounds to the second. Twice in 50 rounds the clock is one no caller should
            // give: its last second, after which every round is earlier, and half its value. The
            // second of the two falls on a TCP round (every fifth), the first does not.
            let steady = (i / 7) as u64;
            let mono_secs = match i % 50 {
                17 => u64::MAX,
                35 => steady / 2,
                _ => steady,
            };
            let now = Now {
                mono_secs,
                unix_secs: rng.next(),
            };
            let transport = if i % 5 == 0 {
                Transport::Tcp
            } else {
                Transport::Udp
            };

            let packet = match rng.below(4) {
                0 => rng.bytes(80),
                1 => query(i as u16, &format!("h{}.example.com", i % 20_000), 1),
                _ => {
                    let base = &queries[rng.below(queries.len())];
                    rng.mutate(base)
                }
            };
            match r.handle_query(&packet, transport, now) {
                Action::Reply(_) => replies += 1,
                Action::Drop => drops += 1,
                Action::Forward(p) => {
                    forwards += 1;
                    assert!(!p.is_refresh());
                    waiting.push(p);
                }
                Action::ReplyAndRefresh(_, p) => {
                    refreshes += 1;
                    assert!(p.is_refresh());
                    // A prefetch only with the switch on, and then it is a refresh like the rest.
                    assert!(prefetch || !p.is_prefetch());
                    prefetches += usize::from(p.is_prefetch());
                    waiting.push(p);
                }
            }
            if waiting.len() > WAITING {
                waiting.remove(0);
            }

            if !waiting.is_empty() {
                let turn = rng.below(waiting.len());
                let p = &waiting[turn];
                let base = match rng.below(6) {
                    n @ 0..=2 => answers[n].clone(),
                    _ => {
                        let mut made = answer_for(p, i as u16);
                        made.metadata.truncation = rng.below(8) == 0;
                        made.to_vec().unwrap()
                    }
                };
                let packet = if rng.below(3) == 0 {
                    base
                } else {
                    rng.mutate(&base)
                };

                let (counted, held) = (r.stats().total(), r.cache_len());
                let outcome = r.handle_upstream(p, &packet, transport, now);
                // Nothing is counted here, whatever the packet.
                assert_eq!(r.stats().total(), counted);
                let answered = match outcome {
                    UpstreamOutcome::Reply(b) => {
                        relays += 1;
                        assert!(!p.is_refresh());
                        assert_eq!(b[..2], p.question.id().to_be_bytes());
                        true
                    }
                    UpstreamOutcome::Refreshed => {
                        refreshed += 1;
                        assert!(p.is_refresh());
                        true
                    }
                    UpstreamOutcome::RetryOverTcp => {
                        retries += 1;
                        assert_eq!((transport, r.cache_len()), (Transport::Udp, held));
                        false
                    }
                    UpstreamOutcome::Mismatch => {
                        mismatches += 1;
                        assert_eq!(r.cache_len(), held);
                        false
                    }
                };
                assert_eq!(p.servfail().is_some(), !p.is_refresh());
                assert_eq!(p.upstream_query(i as u16)[..2], (i as u16).to_be_bytes());
                // A question that got no answer keeps waiting, and may get a late one.
                if answered {
                    waiting.swap_remove(turn);
                }
            }
            assert!(r.cache_len() <= CACHE_CAPACITY);
            fullest = fullest.max(r.cache_len());
        }

        assert!(r.stats().recent(usize::MAX).count() <= QUERY_LOG_CAPACITY);
        // Guards against a run that only ever reaches one branch, or never fills what it bounds.
        let counts = r.stats().total();
        assert!(
            replies > 1_000 && forwards > 1_000 && refreshes > 1_000 && drops > 1_000,
            "{replies} replies, {forwards} forwards, {refreshes} refreshes, {drops} drops"
        );
        assert!(
            relays > 1_000 && refreshed > 1_000 && retries > 1_000 && mismatches > 1_000,
            "{relays} relayed, {refreshed} refreshed, {retries} retries, {mismatches} mismatches"
        );
        // With prefetch on the run reaches it (38 times with this seed); off, never.
        assert!(
            if prefetch {
                prefetches > 10
            } else {
                prefetches == 0
            },
            "{prefetches} prefetches"
        );
        assert!(
            fullest == CACHE_CAPACITY && counts.cache_hits > 1_000,
            "{fullest} answers held at most, {} cache hits",
            counts.cache_hits
        );
        assert!(
            counts.queries as usize > QUERY_LOG_CAPACITY,
            "{} queries logged",
            counts.queries
        );
    }

    // The cost of a cached answer, which is what a prefetch adds a check to. Run in release:
    // cargo test -p qb-dns --release cached_answer_cost -- --ignored --nocapture
    #[test]
    #[ignore = "a timing test for release builds; see the comment above it"]
    fn cached_answer_cost_with_prefetch_on_and_off() {
        use std::hint::black_box;
        use std::time::{Duration, Instant};

        /// The names stored, each asked for in turn.
        const NAMES: usize = 300;
        /// The queries of one pass.
        const QUERIES: usize = 1_000_000;
        /// The passes made with each setting, taking turns; the fastest counts.
        const PASSES: usize = 5;

        let names: Vec<String> = (0..NAMES).map(|i| format!("host{i}.example.com")).collect();
        let packets: Vec<Vec<u8>> = names.iter().map(|name| query(7, name, 1)).collect();
        // Every answer is fresh for an hour from 1000, and asked for at 1100: far from its
        // window, so no pass asks for a prefetch, and what is timed is the cost of the check.
        let resolver_with = |prefetch: bool| {
            let mut r = resolver();
            r.set_prefetch(prefetch);
            for name in &names {
                r.cache
                    .insert(key(name, 1, false), unhex(R_A), 3_600, 1_000);
            }
            r
        };
        let (mut off, mut on) = (resolver_with(false), resolver_with(true));
        let pass = |r: &mut Resolver| {
            let start = Instant::now();
            for i in 0..QUERIES {
                let action =
                    r.handle_query(black_box(&packets[i % NAMES]), Transport::Udp, at(1_100));
                assert!(matches!(black_box(action), Action::Reply(_)));
            }
            start.elapsed()
        };
        let (mut fastest_off, mut fastest_on) = (Duration::MAX, Duration::MAX);
        for _ in 0..PASSES {
            fastest_off = fastest_off.min(pass(&mut off));
            fastest_on = fastest_on.min(pass(&mut on));
        }
        let per_query = |elapsed: Duration| elapsed.as_nanos() / QUERIES as u128;
        println!(
            "{QUERIES} cached answers per pass over {NAMES} names, fastest of {PASSES} passes:"
        );
        println!("  prefetch off: {} ns per query", per_query(fastest_off));
        println!("  prefetch on:  {} ns per query", per_query(fastest_on));
        assert_eq!(off.stats().total().cache_hits, (QUERIES * PASSES) as u64);
        assert_eq!(on.stats().total().cache_hits, (QUERIES * PASSES) as u64);
    }
}
