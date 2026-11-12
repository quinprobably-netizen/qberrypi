//! The alerts that the watchdog raises, and where they go.

/// How much an alert matters. The variants are in order of weight, the lightest first, so that
/// the derived ordering ranks them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Warn,
    High,
}
pub struct Alert {
    pub kind: &'static str,
    pub severity: Severity,
    pub client: Option<std::net::IpAddr>,
    pub subject: String,
}
pub trait AlertSink: Send + Sync {
    fn raise(&self, alert: Alert);
}

pub struct NullSink;

impl AlertSink for NullSink {
    fn raise(&self, _alert: Alert) {}
}
