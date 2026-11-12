//! DNS decisions for qberrypi: blocklists, cache and answers. No sockets;
//! the caller moves the packets.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod answer;
pub mod blockset;
mod cache;
pub mod decide;
mod lru;
pub mod name;
pub mod parse;
mod query;
pub mod stats;
#[cfg(test)]
pub(crate) mod testutil;

pub use blockset::{BlockSet, BlockSetBuilder, InvalidName, ListClass};
pub use decide::{Action, Pending, Resolver, ThreatHit, UpstreamOutcome};
pub use parse::{ListStats, RuleKind};
pub use stats::{Counts, HistoryBucket, LastBlocked, LogEntry, Outcome, Stats};

/// The time of one call: the library reads no clock of its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Now {
    /// Seconds on a monotonic clock, counted from any fixed start.
    pub mono_secs: u64,
    /// Wall-clock seconds since the Unix epoch; may step in either direction.
    pub unix_secs: u64,
}

/// How a client's query arrived, which decides the reply size limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    /// A datagram: replies over the size limit are truncated.
    Udp,
    /// A stream: no size limit.
    Tcp,
}
