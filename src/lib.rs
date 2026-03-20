pub mod agent;
pub mod commands;
pub mod comms;
pub mod connectors;
pub mod mcp;
pub mod monitoring;
pub mod proxy;
pub mod security;
pub mod task;
pub mod transport;
pub mod utils;

// Crate version exposed for runtime queries
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
