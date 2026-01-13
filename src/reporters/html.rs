//! HTML report generator

use crate::core::{Severity, ScanReport};
use crate::reporters::Reporter;
use anyhow::Result;

const HTML_TEMPLATE: &str = include_str!("../../resources/templates/report.html");

/// HTML reporter
#[derive(Debug)]
pub struct HtmlReporter {
    min_severity: Severity,
}

impl HtmlReporter {
    pub fn new() -> Self {
        Self {
            min_severity: Severity::Info,
        }
    }

    pub fn with_min_severity(mut self, severity: Severity) -> Self {
        self.min_severity = severity;
        self
    }

    fn severity_class(severity: Severity) -> &'static str {
        match severity {
            Severity::Critical => "severity-critical",
            Severity::High => "severity-high",
            Severity::Medium => "severity-medium",
            Severity::Low => "severity-low",
            Severity::Info => "severity-info",
        }
    }

    fn severity_icon(severity: Severity) -> &'static str {
        match severity {
            Severity::Critical => "⚠️",
            Severity::High => "",
            Severity::Medium => "",
            Severity::Low => "",
            Severity::Info => "",
        }
    }
}

impl Default for HtmlReporter {
    fn default() -> Self {
        Self::new()
    }
}

impl Reporter for HtmlReporter {
    fn report(&self, scan_report: &ScanReport) -> Result<String> {
        let filter = scan_report
            .findings
            .iter()
            .filter(|f| f.severity >= self.min_severity)
            .collect::<Vec<_>>();

        let findings_html = filter
            .iter()
            .map(|f| {
                format!(
                    r#"<div class="finding {}" data-severity="{}" data-analyzer="{}">
                        <div class="finding-header">
                            <span class="finding-icon">{}</span>
                            <span class="finding-severity">{}</span>
                            <span class="finding-title">{}</span>
                            <span class="finding-rule">{}</span>
                        </div>
                        <div class="finding-details">
                            <div class="finding-location">
                                <span class="label">Location:</span>
                                <code>{}</code>
                            </div>
                            {}
                            {}
                            {}
                            {}
                        </div>
                    </div>"#,
                    Self::severity_class(f.severity),
                    f.severity,
                    f.analyzer,
                    Self::severity_icon(f.severity),
                    f.severity,
                    html_escape::encode_text(&f.title),
                    html_escape::encode_text(&f.rule_id),
                    html_escape::encode_text(&f.location.display()),
                    if !f.description.is_empty() {
                        format!(
                            "<div class='finding-description'>{}</div>",
                            html_escape::encode_text(&f.description)
                        )
                    } else {
                        String::new()
                    },
                    if let Some(evidence) = &f.evidence {
                        format!(
                            "<div class='finding-evidence'><span class='label'>Evidence:</span><code>{}</code></div>",
                            html_escape::encode_text(evidence)
                        )
                    } else {
                        String::new()
                    },
                    if let Some(remediation) = &f.remediation {
                        format!(
                            "<div class='finding-remediation'><span class='label'>Remediation:</span>{}</div>",
                            html_escape::encode_text(remediation)
                        )
                    } else {
                        String::new()
                    },
                    if !f.references.is_empty() {
                        format!(
                            "<div class='finding-references'><span class='label'>References:</span>{}</div>",
                            f.references
                                .iter()
                                .map(|r| format!("<a href='{}' target='_blank'>{}</a>",
                                    html_escape::encode_text(r),
                                    html_escape::encode_text(r)
                                ))
                                .collect::<Vec<_>>()
                                .join(", ")
                        )
                    } else {
                        String::new()
                    },
                )
            })
            .collect::<Vec<_>>()
            .join("\n");

        let summary = &scan_report.summary;

        let html = HTML_TEMPLATE
            .replace("{{REPOSITORY}}", &html_escape::encode_text(&scan_report.repository))
            .replace("{{SCAN_TIME}}", &scan_report.scan_time.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .replace("{{DURATION}}", &format!("{:.2}", scan_report.duration_secs))
            .replace("{{TOTAL}}", &summary.total().to_string())
            .replace("{{CRITICAL}}", &summary.critical.to_string())
            .replace("{{HIGH}}", &summary.high.to_string())
            .replace("{{MEDIUM}}", &summary.medium.to_string())
            .replace("{{LOW}}", &summary.low.to_string())
            .replace("{{INFO}}", &summary.info.to_string())
            .replace("{{FINDINGS}}", &findings_html);

        Ok(html)
    }
}

// Simple HTML escape implementation
mod html_escape {
    pub fn encode_text(s: &str) -> String {
        s.chars()
            .flat_map(|c| match c {
                '&' => "&amp;".chars().collect::<Vec<_>>(),
                '<' => "&lt;".chars().collect::<Vec<_>>(),
                '>' => "&gt;".chars().collect::<Vec<_>>(),
                '"' => "&quot;".chars().collect::<Vec<_>>(),
                '\'' => "&apos;".chars().collect::<Vec<_>>(),
                _ => vec![c],
            })
            .collect()
    }
}
