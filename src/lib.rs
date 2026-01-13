//! Snitch-Checker: Repository Security Benchmarking Library
//!
//! This library provides the core functionality for the snitch-checker CLI tool.

pub mod analyzers;
pub mod cli;
pub mod core;
pub mod git;
pub mod reporters;
pub mod utils;

// Re-export commonly used types
pub use crate::core::{
    Finding, Location, Repository, ScanReport, ScanSummary, Scanner, Severity,
};
pub use crate::reporters::{ConsoleReporter, HtmlReporter, OutputFormat, Reporter, SarifReporter};
