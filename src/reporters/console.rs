//! Console output reporter

use crate::core::{Severity, ScanReport};
use crate::reporters::Reporter;
use anyhow::Result;
use console::{style, Color};

/// Console reporter with colored output
#[derive(Debug)]
pub struct ConsoleReporter {
    min_severity: Severity,
}

impl ConsoleReporter {
    pub fn new() -> Self {
        Self {
            min_severity: Severity::Info,
        }
    }

    pub fn with_min_severity(mut self, severity: Severity) -> Self {
        self.min_severity = severity;
        self
    }

    fn severity_color(severity: Severity) -> Color {
        match severity {
            Severity::Critical => Color::Magenta,
            Severity::High => Color::Red,
            Severity::Medium => Color::Yellow,
            Severity::Low => Color::Blue,
            Severity::Info => Color::Cyan,
        }
    }

    fn format_severity(&self, severity: Severity) -> String {
        let colored = style(severity.to_string())
            .fg(Self::severity_color(severity))
            .bold();
        format!("[{}]", colored)
    }

    fn format_header(&self, text: &str) -> String {
        style(text).bold().underlined().to_string()
    }

    fn format_location(&self, location: &str) -> String {
        style(location).dim().italic().to_string()
    }

    fn format_evidence(&self, evidence: &str) -> String {
        let mut truncated = evidence.to_string();
        if truncated.len() > 80 {
            truncated.truncate(77);
            truncated.push_str("...");
        }
        style(truncated).dim().to_string()
    }
}

impl Default for ConsoleReporter {
    fn default() -> Self {
        Self::new()
    }
}

impl Reporter for ConsoleReporter {
    fn report(&self, scan_report: &ScanReport) -> Result<String> {
        let mut output = String::new();

        // Header
        output.push_str(&format!(
            "\n{}\n",
            self.format_header(&format!("Snitch Security Scan Report"))
        ));
        output.push_str(&style("─".repeat(60)).dim().to_string());
        output.push_str("\n\n");

        // Scan info
        output.push_str(&format!(
            "{}: {}\n",
            style("Repository").bold(),
            scan_report.repository
        ));
        output.push_str(&format!(
            "{}: {}\n",
            style("Scan Time").bold(),
            scan_report.scan_time.format("%Y-%m-%d %H:%M:%S UTC")
        ));
        output.push_str(&format!(
            "{}: {:.2}s\n",
            style("Duration").bold(),
            scan_report.duration_secs
        ));
        output.push('\n');

        // Summary
        let summary = &scan_report.summary;
        output.push_str(&self.format_header("Summary"));
        output.push_str("\n");
        if summary.critical > 0 {
            output.push_str(&format!(
                "  {}: {}\n",
                style("Critical").fg(Color::Magenta).bold(),
                summary.critical
            ));
        }
        if summary.high > 0 {
            output.push_str(&format!(
                "  {}: {}\n",
                style("High").fg(Color::Red).bold(),
                summary.high
            ));
        }
        if summary.medium > 0 {
            output.push_str(&format!(
                "  {}: {}\n",
                style("Medium").fg(Color::Yellow).bold(),
                summary.medium
            ));
        }
        if summary.low > 0 {
            output.push_str(&format!(
                "  {}: {}\n",
                style("Low").fg(Color::Blue).bold(),
                summary.low
            ));
        }
        if summary.info > 0 {
            output.push_str(&format!(
                "  {}: {}\n",
                style("Info").fg(Color::Cyan).bold(),
                summary.info
            ));
        }

        output.push_str(&format!(
            "  {}: {}\n\n",
            style("Total").bold(),
            summary.total()
        ));

        // Filter findings by min severity
        let findings: Vec<_> = scan_report
            .findings
            .iter()
            .filter(|f| f.severity >= self.min_severity)
            .collect();

        if findings.is_empty() {
            output.push_str(&style("No findings above the minimum severity threshold.\n").green().to_string());
        } else {
            // Group findings by severity
            for severity in [
                Severity::Critical,
                Severity::High,
                Severity::Medium,
                Severity::Low,
                Severity::Info,
            ] {
                let severity_findings: Vec<_> = findings
                    .iter()
                    .filter(|f| f.severity == severity)
                    .collect();

                if !severity_findings.is_empty() {
                    output.push_str(&self.format_header(&format!("{} Findings", severity)));
                    output.push_str("\n");

                    for finding in severity_findings {
                        // Severity and title
                        output.push_str(&format!(
                            "{} {}\n",
                            self.format_severity(severity),
                            style(&finding.title).bold()
                        ));

                        // Rule ID
                        output.push_str(&format!(
                            "  {} {}\n",
                            style("Rule:").dim(),
                            finding.rule_id
                        ));

                        // Location
                        output.push_str(&format!(
                            "  {} {}\n",
                            style("Location:").dim(),
                            self.format_location(&finding.location.display())
                        ));

                        // Description
                        if !finding.description.is_empty() {
                            output.push_str(&format!(
                                "  {} {}\n",
                                style("Description:").dim(),
                                finding.description
                            ));
                        }

                        // Evidence
                        if let Some(evidence) = &finding.evidence {
                            output.push_str(&format!(
                                "  {} {}\n",
                                style("Evidence:").dim(),
                                self.format_evidence(evidence)
                            ));
                        }

                        // Remediation
                        if let Some(remediation) = &finding.remediation {
                            output.push_str(&format!(
                                "  {} {}\n",
                                style("Remediation:").dim(),
                                remediation
                            ));
                        }

                        // References
                        if !finding.references.is_empty() {
                            output.push_str(&format!(
                                "  {} {}\n",
                                style("References:").dim(),
                                finding.references.join(", ")
                            ));
                        }

                        output.push('\n');
                    }
                }
            }
        }

        // Footer
        output.push_str(&style("─".repeat(60)).dim().to_string());
        output.push_str("\n");
        output.push_str(&format!(
            "Generated by {}\n",
            style("Snitch-Checker").dim()
        ));

        Ok(output)
    }
}
