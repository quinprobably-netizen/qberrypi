//! Stand-ins for items that other work on qberrypi provides and that are not on this branch yet,
//! and the re-exports of those that are.
//!
//! Each stand-in has the name, fields and meaning of the item it stands in for, so that the
//! integration replaces it by a `pub use` of the real one and nothing else changes.

use qb_dns::{LogEntry, Outcome};
use serde_json::{Value, json};

/// One upstream server's figures since boot: its address, the answers it gave and the times it
/// gave none, and its smoothed round trip.
pub use crate::dns::upstream::ServerStats;

/// One device in the table of the devices that asked: the real `dns::clients::Client`.
pub use crate::dns::clients::Client;

/// The most queries one answer of `/api/v1/queries` lists.
///
/// Stand-in for `status::MAX_QUERIES` (milestone 4/5 Task 11), until the integration replaces it
/// by a `pub use` of that item.
pub const MAX_QUERIES: usize = 1000;

/// One query as JSON: `{"unix_secs", "name", "qtype", "outcome"}`, the outcome one of
/// `"blocked"`, `"local"`, `"cached"`, `"stale"` and `"forwarded"`.
///
/// Stand-in for milestone 4/5 Task 11's JSON for one query, until the integration replaces it by
/// a `pub use` of that item.
pub fn query_json(entry: &LogEntry) -> Value {
    let outcome = match entry.outcome {
        Outcome::Blocked => "blocked",
        Outcome::Local => "local",
        Outcome::Cached => "cached",
        Outcome::Stale => "stale",
        Outcome::Forwarded => "forwarded",
    };
    json!({
        "unix_secs": entry.unix_secs,
        "name": &*entry.name,
        "qtype": entry.qtype,
        "outcome": outcome,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_query_is_its_time_name_type_and_outcome() {
        let entry = |outcome| LogEntry {
            unix_secs: 7,
            name: "a.example.com".into(),
            qtype: 28,
            outcome,
        };
        assert_eq!(
            query_json(&entry(Outcome::Stale)),
            json!({"unix_secs": 7, "name": "a.example.com", "qtype": 28, "outcome": "stale"})
        );
        let outcomes = [
            Outcome::Blocked,
            Outcome::Local,
            Outcome::Cached,
            Outcome::Stale,
            Outcome::Forwarded,
        ];
        let names: Vec<Value> = outcomes
            .map(|o| query_json(&entry(o))["outcome"].take())
            .into();
        assert_eq!(names, ["blocked", "local", "cached", "stale", "forwarded"]);
    }
}
