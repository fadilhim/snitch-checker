//! Core finding types and severity levels

use serde::{Deserialize, Serialize};
use std::fmt;

/// Severity level of a security finding
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// Critical security issue - immediate action required
    Critical = 5,
    /// High severity issue - should be addressed soon
    High = 4,
    /// Medium severity issue - should be addressed
    Medium = 3,
    /// Low severity issue - consider addressing
    Low = 2,
    /// Informational finding - for awareness
    Info = 1,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
            Severity::Info => write!(f, "INFO"),
        }
    }
}

impl std::str::FromStr for Severity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "critical" => Ok(Severity::Critical),
            "high" => Ok(Severity::High),
            "medium" => Ok(Severity::Medium),
            "low" => Ok(Severity::Low),
            "info" => Ok(Severity::Info),
            _ => Err(format!("Invalid severity: {}", s)),
        }
    }
}

impl Severity {
    /// Get the color code for terminal output
    pub fn color_code(&self) -> &str {
        match self {
            Severity::Critical => "\x1b[95m", // Bright red/magenta
            Severity::High => "\x1b[91m",     // Bright red
            Severity::Medium => "\x1b[93m",   // Bright yellow
            Severity::Low => "\x1b[94m",      // Bright blue
            Severity::Info => "\x1b[96m",     // Bright cyan
        }
    }

    /// Get the emoji for the severity level
    pub fn emoji(&self) -> &str {
        match self {
            Severity::Critical => "",
            Severity::High => "",
            Severity::Medium => "",
            Severity::Low => "",
            Severity::Info => "",
        }
    }
}

/// Location of a finding in source code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    /// File path relative to repository root
    pub file: String,
    /// Line number (0-indexed or 1-indexed depending on context)
    pub line: Option<usize>,
    /// Column number
    pub column: Option<usize>,
    /// Git commit hash if available
    pub commit: Option<String>,
}

impl Location {
    /// Create a new location
    pub fn new(file: impl Into<String>) -> Self {
        Self {
            file: file.into(),
            line: None,
            column: None,
            commit: None,
        }
    }

    /// Create a new location with line number
    pub fn with_line(mut self, line: usize) -> Self {
        self.line = Some(line);
        self
    }

    /// Create a new location with column
    pub fn with_column(mut self, column: usize) -> Self {
        self.column = Some(column);
        self
    }

    /// Create a new location with commit
    pub fn with_commit(mut self, commit: impl Into<String>) -> Self {
        self.commit = Some(commit.into());
        self
    }

    /// Format location for display
    pub fn display(&self) -> String {
        match (&self.line, &self.column) {
            (Some(line), Some(col)) => format!("{}:{}:{}", self.file, line + 1, col + 1),
            (Some(line), None) => format!("{}:{}", self.file, line + 1),
            (None, _) => self.file.clone(),
        }
    }
}

/// A security finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Unique identifier for this finding
    pub id: String,
    /// Rule identifier (e.g., "AWS-001", "URL-HARDCODED")
    pub rule_id: String,
    /// Severity level
    pub severity: Severity,
    /// Short title
    pub title: String,
    /// Detailed description
    pub description: String,
    /// Location of the finding
    pub location: Location,
    /// The actual content that matched
    pub evidence: Option<String>,
    /// Suggested remediation
    pub remediation: Option<String>,
    /// Reference links for more information
    pub references: Vec<String>,
    /// Analyzer that produced this finding
    pub analyzer: String,
}

impl Finding {
    /// Create a new finding
    pub fn new(
        rule_id: impl Into<String>,
        severity: Severity,
        title: impl Into<String>,
        location: Location,
        analyzer: impl Into<String>,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            rule_id: rule_id.into(),
            severity,
            title: title.into(),
            description: String::new(),
            location,
            evidence: None,
            remediation: None,
            references: Vec::new(),
            analyzer: analyzer.into(),
        }
    }

    /// Set the description
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Set the evidence
    pub fn with_evidence(mut self, evidence: impl Into<String>) -> Self {
        self.evidence = Some(evidence.into());
        self
    }

    /// Set the remediation
    pub fn with_remediation(mut self, remediation: impl Into<String>) -> Self {
        self.remediation = Some(remediation.into());
        self
    }

    /// Add a reference link
    pub fn with_reference(mut self, reference: impl Into<String>) -> Self {
        self.references.push(reference.into());
        self
    }
}

/// Summary statistics for a scan
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanSummary {
    /// Number of critical findings
    pub critical: usize,
    /// Number of high findings
    pub high: usize,
    /// Number of medium findings
    pub medium: usize,
    /// Number of low findings
    pub low: usize,
    /// Number of info findings
    pub info: usize,
}

impl ScanSummary {
    /// Create a new summary from findings
    pub fn from_findings(findings: &[Finding]) -> Self {
        let mut summary = Self::default();
        for finding in findings {
            match finding.severity {
                Severity::Critical => summary.critical += 1,
                Severity::High => summary.high += 1,
                Severity::Medium => summary.medium += 1,
                Severity::Low => summary.low += 1,
                Severity::Info => summary.info += 1,
            }
        }
        summary
    }

    /// Total number of findings
    pub fn total(&self) -> usize {
        self.critical + self.high + self.medium + self.low + self.info
    }

    /// Get the maximum severity found
    pub fn max_severity(&self) -> Option<Severity> {
        if self.critical > 0 {
            Some(Severity::Critical)
        } else if self.high > 0 {
            Some(Severity::High)
        } else if self.medium > 0 {
            Some(Severity::Medium)
        } else if self.low > 0 {
            Some(Severity::Low)
        } else if self.info > 0 {
            Some(Severity::Info)
        } else {
            None
        }
    }
}

/// Complete scan report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    /// Repository path or URL
    pub repository: String,
    /// When the scan was performed
    pub scan_time: chrono::DateTime<chrono::Utc>,
    /// All findings discovered
    pub findings: Vec<Finding>,
    /// Summary statistics
    pub summary: ScanSummary,
    /// Duration of the scan
    pub duration_secs: f64,
    /// Analyzers that were run
    pub analyzers: Vec<String>,
}

impl ScanReport {
    /// Create a new scan report
    pub fn new(repository: impl Into<String>, analyzers: Vec<String>) -> Self {
        Self {
            repository: repository.into(),
            scan_time: chrono::Utc::now(),
            findings: Vec::new(),
            summary: ScanSummary::default(),
            duration_secs: 0.0,
            analyzers,
        }
    }

    /// Update the summary based on current findings
    pub fn update_summary(&mut self) {
        self.summary = ScanSummary::from_findings(&self.findings);
    }

    /// Filter findings by minimum severity
    pub fn filter_by_severity(&self, min_severity: Severity) -> Vec<&Finding> {
        self.findings
            .iter()
            .filter(|f| f.severity >= min_severity)
            .collect()
    }

    /// Get findings by analyzer
    pub fn findings_by_analyzer(&self, analyzer: &str) -> Vec<&Finding> {
        self.findings
            .iter()
            .filter(|f| f.analyzer == analyzer)
            .collect()
    }
}
