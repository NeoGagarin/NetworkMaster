//! Read-only `EdgeOS` collection using pinned SSH and fixed operational commands.
pub mod collector;
pub mod parse;
pub use collector::EdgeOsCollector;
