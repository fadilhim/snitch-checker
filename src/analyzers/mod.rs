//! Security analyzers

use crate::core::{Finding, Repository};
use anyhow::Result;
use std::fmt;

pub mod urls;
pub mod secrets;
pub mod file_ops;
pub mod dependencies;

/// Trait for security analyzers
pub trait Analyzer: fmt::Debug + Send + Sync {
    /// Get the analyzer name
    fn name(&self) -> &str;

    /// Get a short description of what this analyzer checks
    fn description(&self) -> &str;

    /// Check if this analyzer is enabled by default
    fn enabled_by_default(&self) -> bool {
        true
    }

    /// Analyze a repository and return findings
    fn analyze(&self, repo: &dyn Repository) -> Result<Vec<Finding>>;
}

/// Registry of available analyzers
#[derive(Debug)]
pub struct AnalyzerRegistry {
    analyzers: Vec<Box<dyn Analyzer>>,
    enabled: Vec<String>,
    disabled: Vec<String>,
}

impl Default for AnalyzerRegistry {
    fn default() -> Self {
        let mut registry = Self {
            analyzers: Vec::new(),
            enabled: Vec::new(),
            disabled: Vec::new(),
        };

        // Register default analyzers
        registry.register(Box::new(urls::UrlAnalyzer::new()));
        registry.register(Box::new(secrets::SecretsAnalyzer::new()));
        registry.register(Box::new(file_ops::FileOpsAnalyzer::new()));
        registry.register(Box::new(dependencies::DependenciesAnalyzer::new()));

        registry
    }
}

impl AnalyzerRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            analyzers: Vec::new(),
            enabled: Vec::new(),
            disabled: Vec::new(),
        }
    }

    /// Register an analyzer
    pub fn register(&mut self, analyzer: Box<dyn Analyzer>) {
        let name = analyzer.name().to_string();
        if analyzer.enabled_by_default() {
            self.enabled.push(name.clone());
        }
        self.analyzers.push(analyzer);
    }

    /// Enable an analyzer by name
    pub fn enable(&mut self, name: &str) -> Result<()> {
        let names: Vec<_> = self.analyzers.iter().map(|a| a.name()).collect();
        if !names.contains(&name) {
            anyhow::bail!("Unknown analyzer: {}", name);
        }
        self.disabled.retain(|n| n != name);
        if !self.enabled.contains(&name.to_string()) {
            self.enabled.push(name.to_string());
        }
        Ok(())
    }

    /// Disable an analyzer by name
    pub fn disable(&mut self, name: &str) -> Result<()> {
        let names: Vec<_> = self.analyzers.iter().map(|a| a.name()).collect();
        if !names.contains(&name) {
            anyhow::bail!("Unknown analyzer: {}", name);
        }
        self.enabled.retain(|n| n != name);
        if !self.disabled.contains(&name.to_string()) {
            self.disabled.push(name.to_string());
        }
        Ok(())
    }

    /// Enable only specific analyzers
    pub fn enable_only(&mut self, names: &[String]) -> Result<()> {
        let valid_names: Vec<_> = self.analyzers.iter().map(|a| a.name()).collect();

        for name in names {
            if !valid_names.contains(&name.as_str()) {
                anyhow::bail!("Unknown analyzer: {}", name);
            }
        }

        self.enabled = names.to_vec();
        self.disabled = valid_names
            .into_iter()
            .filter(|n| !names.contains(&n.to_string()))
            .map(|s| s.to_string())
            .collect();

        Ok(())
    }

    /// Get all enabled analyzers
    pub fn enabled(&self) -> Vec<&dyn Analyzer> {
        self.analyzers
            .iter()
            .filter(|a| self.enabled.contains(&a.name().to_string()))
            .map(|a| a.as_ref())
            .collect()
    }

    /// Get all registered analyzer names
    pub fn all_names(&self) -> Vec<String> {
        self.analyzers.iter().map(|a| a.name().to_string()).collect()
    }

    /// List available analyzers with descriptions
    pub fn list(&self) -> Vec<(String, String, bool)> {
        self.analyzers
            .iter()
            .map(|a| {
                (
                    a.name().to_string(),
                    a.description().to_string(),
                    self.enabled.contains(&a.name().to_string()),
                )
            })
            .collect()
    }
}
