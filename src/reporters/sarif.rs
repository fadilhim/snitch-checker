//! SARIF (Static Analysis Results Interchange Format) reporter

use crate::core::{Severity, ScanReport};
use crate::reporters::Reporter;
use anyhow::Result;
use serde_json::json;

/// SARIF reporter for IDE integration and CI/CD
#[derive(Debug)]
pub struct SarifReporter {
    tool_name: String,
    tool_version: String,
    min_severity: Severity,
}

impl SarifReporter {
    pub fn new() -> Self {
        Self {
            tool_name: "snitch-checker".to_string(),
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            min_severity: Severity::Info,
        }
    }

    pub fn with_min_severity(mut self, severity: Severity) -> Self {
        self.min_severity = severity;
        self
    }

    fn severity_to_level(severity: Severity) -> &'static str {
        match severity {
            Severity::Critical => "error",
            Severity::High => "error",
            Severity::Medium => "warning",
            Severity::Low => "note",
            Severity::Info => "note",
        }
    }

    fn severity_to_rank(severity: Severity) -> f64 {
        match severity {
            Severity::Critical => 100.0,
            Severity::High => 75.0,
            Severity::Medium => 50.0,
            Severity::Low => 25.0,
            Severity::Info => 0.0,
        }
    }
}

impl Default for SarifReporter {
    fn default() -> Self {
        Self::new()
    }
}

impl Reporter for SarifReporter {
    fn report(&self, scan_report: &ScanReport) -> Result<String> {
        let findings: Vec<_> = scan_report
            .findings
            .iter()
            .filter(|f| f.severity >= self.min_severity)
            .collect();

        let mut results = Vec::new();

        for finding in &findings {
            let mut result = json!({
                "ruleId": finding.rule_id,
                "level": Self::severity_to_level(finding.severity),
                "message": {
                    "text": finding.title.clone()
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.location.file.clone()
                        },
                        "region": {
                            "startLine": finding.location.line.unwrap_or(1) + 1,
                        }
                    }
                }]
            });

            // Add column if available
            if let Some(col) = finding.location.column {
                if let Some(region) = result
                    .pointer_mut("/locations/0/physicalLocation/region")
                    .and_then(|r| r.as_object_mut())
                {
                    region.insert("startColumn".to_string(), json!(col + 1));
                }
            }

            // Add description
            if !finding.description.is_empty() {
                result["message"]["text"] = json!(format!(
                    "{}\n\n{}",
                    finding.title, finding.description
                ));
            }

            // Add evidence
            if let Some(evidence) = &finding.evidence {
                result["fingerprints"] = json!({
                    "evidence": evidence.chars().take(100).collect::<String>()
                });
            }

            // Add remediation as fix
            if let Some(remediation) = &finding.remediation {
                result["fixes"] = json!([{
                    "description": {
                        "text": remediation
                    }
                }]);
            }

            // Add references
            if !finding.references.is_empty() {
                result["relatedLocations"] = finding.references.iter().map(|ref_url| {
                    json!({
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": ref_url
                            }
                        }
                    })
                }).collect();
            }

            results.push(result);
        }

        // Build rules from unique rule IDs
        let mut rules = serde_json::Map::new();
        for finding in &findings {
            if !rules.contains_key(&finding.rule_id) {
                rules.insert(
                    finding.rule_id.clone(),
                    json!({
                        "id": finding.rule_id,
                        "name": finding.rule_id,
                        "shortDescription": {
                            "text": finding.title
                        },
                        "fullDescription": {
                            "text": finding.description
                        },
                        "help": {
                            "text": finding.remediation.as_ref().unwrap_or(&"No remediation available".to_string()).clone()
                        },
                        "defaultConfiguration": {
                            "level": Self::severity_to_level(finding.severity)
                        },
                        "properties": {
                            "severity": finding.severity.to_string(),
                            "analyzer": finding.analyzer
                        }
                    }),
                );
            }
        }

        let sarif = json!({
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": self.tool_name,
                        "version": self.tool_version,
                        "informationUri": "https://github.com/user/snitch-checker",
                        "rules": rules.values().collect::<Vec<_>>()
                    }
                },
                "results": results,
                "invocation": {
                    "startTimeUtc": scan_report.scan_time.to_rfc3339(),
                    "endTimeUtc": scan_report.scan_time.to_rfc3339(),
                    "toolExecutionNotifications": [{
                        "level": "info",
                        "message": {
                            "text": format!("Scan completed in {:.2}s", scan_report.duration_secs)
                        }
                    }]
                },
                "artifacts": [{
                    "location": {
                        "uri": scan_report.repository
                    },
                    "description": {
                        "text": "Scanned repository"
                    }
                }]
            }]
        });

        Ok(serde_json::to_string_pretty(&sarif)?)
    }
}
