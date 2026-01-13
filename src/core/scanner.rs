//! Main scanner orchestrator

use crate::analyzers::AnalyzerRegistry;
use crate::core::{repository::Repository, ScanReport};
use anyhow::Result;
use indicatif::{ProgressBar, ProgressStyle};
use std::time::Instant;

/// Main security scanner
pub struct Scanner {
    registry: AnalyzerRegistry,
}

impl Scanner {
    /// Create a new scanner with the default analyzer registry
    pub fn new() -> Self {
        Self {
            registry: AnalyzerRegistry::default(),
        }
    }

    /// Create a new scanner with a custom analyzer registry
    pub fn with_registry(registry: AnalyzerRegistry) -> Self {
        Self { registry }
    }

    /// Get a reference to the analyzer registry
    pub fn registry(&self) -> &AnalyzerRegistry {
        &self.registry
    }

    /// Get a mutable reference to the analyzer registry
    pub fn registry_mut(&mut self) -> &mut AnalyzerRegistry {
        &mut self.registry
    }

    /// Scan a repository
    pub fn scan(&self, repo: &dyn Repository) -> Result<ScanReport> {
        self.scan_with_progress(repo, false)
    }

    /// Scan a repository with progress bar
    pub fn scan_with_progress(
        &self,
        repo: &dyn Repository,
        show_progress: bool,
    ) -> Result<ScanReport> {
        let start = Instant::now();

        let analyzers = self.registry.enabled();
        let analyzer_names: Vec<String> = analyzers.iter().map(|a| a.name().to_string()).collect();

        let mut report = ScanReport::new(repo.name(), analyzer_names.clone());
        let mut all_findings = Vec::new();

        if show_progress {
            let progress = ProgressBar::new(analyzers.len() as u64);
            progress.set_style(
                ProgressStyle::default_bar()
                    .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {msg}")
                    .unwrap()
                    .progress_chars("##-"),
            );

            for analyzer in analyzers {
                progress.set_message(format!("Running {} analyzer", analyzer.name()));
                match analyzer.analyze(repo) {
                    Ok(findings) => {
                        all_findings.extend(findings);
                    }
                    Err(e) => {
                        eprintln!("Error in {} analyzer: {}", analyzer.name(), e);
                    }
                }
                progress.inc(1);
            }
            progress.finish_with_message("Scan complete");
        } else {
            for analyzer in analyzers {
                match analyzer.analyze(repo) {
                    Ok(findings) => {
                        all_findings.extend(findings);
                    }
                    Err(e) => {
                        eprintln!("Error in {} analyzer: {}", analyzer.name(), e);
                    }
                }
            }
        }

        report.findings = all_findings;
        report.update_summary();
        report.duration_secs = start.elapsed().as_secs_f64();

        Ok(report)
    }

    /// Scan a repository and only return findings above a severity threshold
    pub fn scan_filtered(
        &self,
        repo: &dyn Repository,
        min_severity: crate::core::Severity,
    ) -> Result<ScanReport> {
        let mut report = self.scan(repo)?;
        report.findings = report
            .findings
            .into_iter()
            .filter(|f| f.severity >= min_severity)
            .collect();
        report.update_summary();
        Ok(report)
    }
}

impl Default for Scanner {
    fn default() -> Self {
        Self::new()
    }
}
