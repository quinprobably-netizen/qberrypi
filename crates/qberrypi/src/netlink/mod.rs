//! Netlink, implemented in this crate: no netlink crate is used.
//!
//! `wire` is the message format, built and read as bytes; it is re-exported
//! here. `socket` sends requests and reads replies, `route` holds the route
//! netlink messages that `net` uses to set up the static network, and
//! `nl80211` holds the Wi-Fi commands and the client that sends them.

pub mod nl80211;
pub mod route;
pub mod socket;
mod wire;

pub use route::{Link, Route};
pub use socket::{NlSocket, REPLY_TIMEOUT, RequestError};
pub use wire::*;
