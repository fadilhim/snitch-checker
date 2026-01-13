//! Secrets and credential scanning

use crate::analyzers::Analyzer;
use crate::core::{Finding, Location, Repository, Severity};
use anyhow::Result;
use regex::Regex;

/// Secret patterns with rule ID, description, and severity
const SECRET_PATTERNS: &[(&str, &str, &str, Severity)] = &[
    // AWS credentials
    (
        r#"(?i)(?:aws_access_key_id|aws_secret_access_key)\s*[:=]\s*['\"]([A-Z0-9]{20})['\"]"#,
        "AWS-001",
        "AWS Access Key ID detected",
        Severity::Critical,
    ),
    (
        r#"(?i)(?:aws_secret_access_key|aws_session_token)\s*[:=]\s*['\"]([A-Za-z0-9/+=]{40})['\"]"#,
        "AWS-002",
        "AWS Secret Access Key detected",
        Severity::Critical,
    ),
    // GitHub tokens
    (
        r"(?i)gh[pu]_[A-Za-z0-9]{36}",
        "GITHUB-001",
        "GitHub personal access token detected",
        Severity::Critical,
    ),
    (
        r"(?i)gho_[A-Za-z0-9]{36}",
        "GITHUB-002",
        "GitHub OAuth token detected",
        Severity::Critical,
    ),
    (
        r"(?i)ghs_[A-Za-z0-9]{36}",
        "GITHUB-003",
        "GitHub server token detected",
        Severity::Critical,
    ),
    // API keys (generic pattern with context)
    (
        r#"(?i)(?:api[_-]?key|apikey|api-key)\s*[:=]\s*['\"]([A-Za-z0-9_\-]{32,})['\"]"#,
        "API-001",
        "Potential API key detected",
        Severity::High,
    ),
    // Slack tokens
    (
        r"xox[baprs]-[A-Za-z0-9\-]{10,}",
        "SLACK-001",
        "Slack token detected",
        Severity::Critical,
    ),
    // Stripe
    (
        r"(?i)sk_(live|test)_[A-Za-z0-9]{24,}",
        "STRIPE-001",
        "Stripe API key detected",
        Severity::Critical,
    ),
    // Google Cloud
    (
        r"(?i)ya29\.[A-Za-z0-9\-_]{100,}",
        "GCP-001",
        "Google OAuth 2.0 token detected",
        Severity::Critical,
    ),
    (
        r"(?i)AIza[A-Za-z0-9\-_]{35}",
        "GCP-002",
        "Google API key detected",
        Severity::High,
    ),
    // Database connection strings with passwords
    (
        r"(?i)(?:mongodb|redis|postgres|mysql)://[^\s:]+:[^\s@]+@[^\s/]+",
        "DB-001",
        "Database connection string with hardcoded credentials",
        Severity::Critical,
    ),
    // JWT tokens
    (
        r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",
        "JWT-001",
        "JWT (JSON Web Token) detected",
        Severity::High,
    ),
    // Private keys
    (
        r"-----BEGIN[A-Z\s]+PRIVATE KEY-----",
        "KEY-001",
        "Private key detected",
        Severity::Critical,
    ),
    (
        r"-----BEGIN RSA PRIVATE KEY-----",
        "KEY-002",
        "RSA private key detected",
        Severity::Critical,
    ),
    (
        r"-----BEGIN EC PRIVATE KEY-----",
        "KEY-003",
        "EC private key detected",
        Severity::Critical,
    ),
    (
        r"-----BEGIN OPENSSH PRIVATE KEY-----",
        "KEY-004",
        "OpenSSH private key detected",
        Severity::Critical,
    ),
    (
        r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
        "KEY-005",
        "PGP private key detected",
        Severity::Critical,
    ),
    // Certificates
    (
        r"-----BEGIN CERTIFICATE-----",
        "CERT-001",
        "Certificate detected (may contain sensitive information)",
        Severity::Medium,
    ),
    // passwords
    (
        r#"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"]([^\s'\"]{8,})['\"]"#,
        "AUTH-001",
        "Hardcoded password detected",
        Severity::High,
    ),
    // Authorization headers
    (
        r#"(?i)(?:authorization|auth)\s*[:=]\s*['\"](?:bearer|basic)\s+[A-Za-z0-9\-_=.]{20,}"#,
        "AUTH-002",
        "Authorization header with credentials detected",
        Severity::Critical,
    ),
];

/// High entropy string pattern (for detecting base64-encoded secrets)
const ENTROPY_REGEX: &str = r"[A-Za-z0-9+/]{40,}={0,2}";
const ENTROPY_THRESHOLD: f64 = 4.5;

/// Suspicious file names that might contain secrets
const SECRET_FILE_PATTERNS: &[(&str, &str, Severity)] = &[
    (r"(?i)\.env$", "Environment file", Severity::High),
    (r"(?i)\.env\.(local|development|production)$", "Environment file", Severity::High),
    (r"(?i)\.pem$", "PEM certificate/key file", Severity::High),
    (r"(?i)\.key$", "Private key file", Severity::Critical),
    (r"(?i)\.pkcs8$", "PKCS8 key file", Severity::Critical),
    (r"(?i)\.der$", "DER encoded file (may be a key)", Severity::High),
    (r"(?i)credentials\.json$", "Credentials file", Severity::High),
    (r"(?i)secrets\.(yaml|yml|json|toml)$", "Secrets configuration", Severity::High),
    (r"(?i)\.aws/credentials$", "AWS credentials file", Severity::Critical),
    (r"(?i)id_rsa$", "SSH private key", Severity::Critical),
    (r"(?i)\.ovpn$", "OpenVPN configuration file", Severity::High),
    (r"(?i)keystore$", "Java keystore file", Severity::High),
    (r"(?i)truststore$", "Java truststore file", Severity::Medium),
];

#[derive(Debug)]
pub struct SecretsAnalyzer {
    patterns: Vec<(Regex, &'static str, &'static str, Severity)>,
    file_patterns: Vec<(Regex, &'static str, Severity)>,
    entropy_regex: Regex,
}

impl SecretsAnalyzer {
    pub fn new() -> Self {
        let patterns: Vec<_> = SECRET_PATTERNS
            .iter()
            .map(|(pattern, id, desc, sev)| {
                (
                    Regex::new(pattern).unwrap_or_else(|_| {
                        panic!("Invalid secret pattern: {}", pattern)
                    }),
                    *id,
                    *desc,
                    *sev,
                )
            })
            .collect();

        let file_patterns: Vec<_> = SECRET_FILE_PATTERNS
            .iter()
            .map(|(pattern, desc, sev)| {
                (
                    Regex::new(pattern).unwrap(),
                    *desc,
                    *sev,
                )
            })
            .collect();

        let entropy_regex = Regex::new(ENTROPY_REGEX).unwrap();

        Self {
            patterns,
            file_patterns,
            entropy_regex,
        }
    }

    /// Calculate Shannon entropy of a string
    fn calculate_entropy(text: &str) -> f64 {
        if text.is_empty() {
            return 0.0;
        }

        let mut freq = [0usize; 256];
        let len = text.len();

        for byte in text.bytes() {
            freq[byte as usize] += 1;
        }

        let mut entropy = 0.0;
        for count in freq {
            if count > 0 {
                let p = count as f64 / len as f64;
                entropy -= p * p.log2();
            }
        }

        entropy
    }

    fn scan_content(&self, content: &str, file: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = content.lines().collect();

        for (line_idx, line) in lines.iter().enumerate() {
            // Check against known patterns
            for (regex, rule_id, desc, severity) in &self.patterns {
                for mat in regex.find_iter(line) {
                    let location = Location::new(file)
                        .with_line(line_idx)
                        .with_column(mat.start());

                    findings.push(
                        Finding::new(*rule_id, *severity, *desc, location, "secrets")
                            .with_evidence(mat.as_str().to_string())
                            .with_remediation("Remove credentials from code and use environment variables or a secret management system")
                            .with_reference("https://cwe.mitre.org/data/definitions/798.html")
                    );
                }
            }

            // Check for high-entropy strings (potential base64 secrets)
            for mat in self.entropy_regex.find_iter(line) {
                let text = mat.as_str();
                let entropy = Self::calculate_entropy(text);

                if entropy >= ENTROPY_THRESHOLD {
                    // Skip obvious non-secrets
                    if text.len() < 40 || text.contains('/') {
                        continue;
                    }

                    let location = Location::new(file)
                        .with_line(line_idx)
                        .with_column(mat.start());

                    findings.push(
                        Finding::new(
                            "SECRET-ENTROPY",
                            Severity::Medium,
                            format!("High-entropy string detected (entropy: {:.2})", entropy),
                            location,
                            "secrets",
                        )
                        .with_evidence(format!("{} (truncated)", &text[..text.len().min(20)]))
                        .with_remediation("Review this high-entropy string - it may be an encoded secret")
                    );
                }
            }
        }

        findings
    }
}

impl Default for SecretsAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for SecretsAnalyzer {
    fn name(&self) -> &str {
        "secrets"
    }

    fn description(&self) -> &str {
        "Scans for hardcoded secrets, credentials, and private keys"
    }

    fn analyze(&self, repo: &dyn Repository) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // First, check for suspicious file names
        for file_path in repo.files()? {
            let file_str = file_path.to_string_lossy();
            let file_str_ref: &str = file_str.as_ref();

            for (regex, desc, severity) in &self.file_patterns {
                if regex.is_match(file_str_ref) {
                    findings.push(
                        Finding::new(
                            "SECRET-FILE",
                            *severity,
                            format!("Suspicious file detected: {}", desc),
                            Location::new(file_str_ref),
                            "secrets",
                        )
                        .with_remediation("Ensure this file is not committed to version control")
                        .with_reference("https://github.com/github/gitignore")
                    );
                }
            }

            // Then scan file content
            match repo.file_content(&file_path) {
                Ok(content) => {
                    findings.extend(self.scan_content(&content, file_str_ref));
                }
                Err(_) => continue, // Skip files we can't read
            }
        }

        Ok(findings)
    }
}
