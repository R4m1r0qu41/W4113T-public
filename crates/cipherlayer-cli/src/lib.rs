//! CipherLayer CLI library: the pipeline orchestrator and demo driver.
//!
//! The CLI is presentation code. It renders decisions; it does not make them.
//! All security decisions live in the trust-spine crates; the binary in
//! main.rs is argument parsing plus rendering.

pub mod console;
pub mod demo;
pub mod pipeline;
pub mod serve;
