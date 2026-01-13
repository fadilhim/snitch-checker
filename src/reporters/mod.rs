//! Reporters for scan results

use crate::core::ScanReport;
use anyhow::Result;

pub mod console;
pub mod html;
pub mod sarif;

/// Trait for reporters
pub trait Reporter {
    /// Generate a report from scan results
    fn report(&self, scan_report: &ScanReport) -> Result<String>;
}

/// Output format for reports
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Console,
    Html,
    Sarif,
}

impl OutputFormat {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "console" | "text" => Some(OutputFormat::Console),
            "html" => Some(OutputFormat::Html),
            "sarif" | "json" => Some(OutputFormat::Sarif),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            OutputFormat::Console => "console",
            OutputFormat::Html => "html",
            OutputFormat::Sarif => "sarif",
        }
    }
}

pub use console::ConsoleReporter;
pub use html::HtmlReporter;
pub use sarif::SarifReporter;
