//! Core types and abstractions for the security scanner

mod findings;
mod repository;
mod scanner;

pub use findings::{Finding, Location, ScanReport, ScanSummary, Severity};
pub use repository::{CommitInfo, GitRepository, LocalRepository, Repository};
pub use scanner::Scanner;
