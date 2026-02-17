//! Internal implementation details

pub mod client;
pub mod message_parser;
pub mod query_full;
#[cfg(target_os = "linux")]
pub mod sandbox;
pub mod transport;
