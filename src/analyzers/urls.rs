//! URL and domain analysis

use crate::analyzers::Analyzer;
use crate::core::{Finding, Location, Repository, Severity};
use anyhow::Result;
use regex::Regex;

/// Suspicious URL patterns and endpoints
const SUSPICIOUS_PATTERNS: &[(&str, &str, Severity)] = &[
    // Hardcoded AWS credentials
    (r"(?i)\b(https?://[a-z0-9\-]+\.s3\.amazonaws\.com/[^\s]+[A-Za-z0-9/=_\-]{20,})", "Hardcoded S3 URL with potential access key", Severity::High),
    (r"(?i)\b(https?://[a-z0-9\-]+\.s3\.amazonaws\.com)", "Hardcoded S3 endpoint", Severity::Low),
    // Hardcoded database URLs
    (r"(?i)\b(mongodb\+srv://[^\s:]+:[^\s@]+@[^\s/]+)", "Hardcoded MongoDB connection string", Severity::Critical),
    (r"(?i)\b(redis://[^\s:]+:[^\s@]+@[^\s/]+)", "Hardcoded Redis connection string", Severity::Critical),
    (r"(?i)\b(postgres|postgresql)://[^\s:]+:[^\s@]+@[^\s/]+)", "Hardcoded PostgreSQL connection string", Severity::Critical),
    (r"(?i)\b(mysql)://[^\s:]+:[^\s@]+@[^\s/]+)", "Hardcoded MySQL connection string", Severity::Critical),
    // API endpoints
    (r#"(?i)\b(https?://(api\.|www\.)?[a-z0-9\-]+\.com/[^\s"]{20,})"#, "Potential hardcoded API endpoint", Severity::Medium),
    (r"(?i)\b(https?://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})[:/]", "Direct IP address URL", Severity::Medium),
    // Suspicious domains
    (r"(?i)\b(pastebin\.com|gist\.github\.com)/[a-z0-9]+", "Possible leaked content on paste site", Severity::High),
    (r"(?i)\b(127\.0\.0\.1|localhost|0\.0\.0\.0)(:[0-9]+)?", "Local development endpoint (may indicate dev config in prod)", Severity::Info),
    // Insecure protocols
    (r#"(?i)\bftp://[^\s"]+"#, "FTP URL (insecure protocol)", Severity::Medium),
    (r#"(?i)\bhttp://[^\s"]+\.amazonaws\.com"#, "HTTP (not HTTPS) URL for AWS", Severity::High),
];

/// Suspicious TLDs and indicators
const SUSPICIOUS_DOMAINS: &[(&str, Severity)] = &[
    (".onion", Severity::High),          // Tor hidden service
    (".bit", Severity::Medium),          // Namecoin
    (".local", Severity::Info),          // Local network
    ("test", Severity::Info),            // Test domain
];

#[derive(Debug)]
pub struct UrlAnalyzer {
    url_regexes: Vec<(Regex, &'static str, Severity)>,
    domain_regexes: Vec<(Regex, Severity)>,
}

impl UrlAnalyzer {
    pub fn new() -> Self {
        let url_regexes: Vec<_> = SUSPICIOUS_PATTERNS
            .iter()
            .map(|(pattern, desc, sev)| {
                (
                    Regex::new(pattern).unwrap_or_else(|_| {
                        panic!("Invalid URL pattern: {}", pattern)
                    }),
                    *desc,
                    *sev,
                )
            })
            .collect();

        let domain_regexes: Vec<_> = SUSPICIOUS_DOMAINS
            .iter()
            .map(|(domain, sev)| {
                (
                    Regex::new(&regex::escape(domain)).unwrap(),
                    *sev,
                )
            })
            .collect();

        Self {
            url_regexes,
            domain_regexes,
        }
    }

    fn scan_content(&self, content: &str, file: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = content.lines().collect();

        for (line_idx, line) in lines.iter().enumerate() {
            // Check URL patterns
            for (regex, desc, severity) in &self.url_regexes {
                for mat in regex.find_iter(line) {
                    let location = Location::new(file)
                        .with_line(line_idx)
                        .with_column(mat.start());

                    findings.push(
                        Finding::new(
                            "URL-HARDCODED",
                            *severity,
                            *desc,
                            location,
                            "url",
                        )
                        .with_evidence(mat.as_str().to_string())
                        .with_remediation("Move sensitive URLs to environment variables or configuration files")
                    );
                }
            }

            // Check for suspicious domains
            for (regex, severity) in &self.domain_regexes {
                for mat in regex.find_iter(line) {
                    let location = Location::new(file)
                        .with_line(line_idx)
                        .with_column(mat.start());

                    findings.push(
                        Finding::new(
                            "URL-SUSPICIOUS-DOMAIN",
                            *severity,
                            format!("Suspicious domain detected: {}", mat.as_str()),
                            location,
                            "url",
                        )
                        .with_evidence(mat.as_str().to_string())
                    );
                }
            }
        }

        findings
    }
}

impl Default for UrlAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for UrlAnalyzer {
    fn name(&self) -> &str {
        "url"
    }

    fn description(&self) -> &str {
        "Scans for hardcoded URLs, connection strings, and suspicious domains"
    }

    fn analyze(&self, repo: &dyn Repository) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Scan all files
        for file_path in repo.files()? {
            // Skip common URL-containing config files that are expected
            let file_str = file_path.to_string_lossy();
            if file_str.contains("package-lock.json")
                || file_str.contains("yarn.lock")
                || file_str.contains("Cargo.lock")
            {
                continue;
            }

            match repo.file_content(&file_path) {
                Ok(content) => {
                    findings.extend(self.scan_content(&content, &file_str));
                }
                Err(_) => continue, // Skip files we can't read
            }
        }

        // Check Git remotes
        for url in repo.remote_urls()? {
            if url.contains("http://") && !url.contains("localhost") {
                findings.push(
                    Finding::new(
                        "GIT-INSECURE-REMOTE",
                        Severity::Medium,
                        "Git remote uses insecure HTTP protocol",
                        Location::new(".git/config"),
                        "url",
                    )
                    .with_evidence(url.clone())
                    .with_remediation("Change remote URL to use HTTPS with SSH or HTTPS protocol")
                );
            }
        }

        Ok(findings)
    }
}
