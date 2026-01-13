//! Dependency vulnerability scanning

use crate::analyzers::Analyzer;
use crate::core::{Finding, Location, Repository, Severity};
use anyhow::Result;
use regex::Regex;
use std::collections::HashMap;

/// Known vulnerable package patterns (for demonstration)
/// In production, this would query OSV, Snyk, or similar databases
const KNOWN_VULNERABILITIES: &[(&str, &str, &str, &str, Severity)] = &[
    // (package_name, version_pattern, cve_id, description, severity)
    ("lodash", "4.17.15", "CVE-2020-8203", "Prototype pollution in lodash", Severity::High),
    ("lodash", "4.17.19", "CVE-2021-23337", "Command injection in lodash", Severity::Critical),
    ("axios", "0.21.1", "CVE-2021-3749", "SSRF in axios", Severity::High),
    ("moment", "2.29.1", "CVE-2022-24785", "Path traversal in moment.js", Severity::Medium),
    ("webpack", "5.0.0", "CVE-2021-37873", "Path traversal in webpack", Severity::Medium),
    ("minimist", "1.2.5", "CVE-2021-44906", "Prototype pollution", Severity::High),
];

/// Dependency file patterns
const DEPENDENCY_FILES: &[(&str, &str, &str)] = &[
    (r"(?i)^package\.json$", "javascript", "npm/Node.js"),
    (r"(?i)^package-lock\.json$", "javascript", "npm lock file"),
    (r"(?i)^yarn\.lock$", "javascript", "Yarn lock file"),
    (r"(?i)^pnpm-lock\.yaml$", "javascript", "pnpm lock file"),
    (r"(?i)^requirements\.txt$", "python", "pip requirements"),
    (r"(?i)^Pipfile$", "python", "Pipenv dependencies"),
    (r"(?i)^poetry\.lock$", "python", "Poetry lock file"),
    (r"(?i)^pyproject\.toml$", "python", "Python project config"),
    (r"(?i)^setup\.py$", "python", "Python setup file"),
    (r"(?i)^Cargo\.toml$", "rust", "Rust dependencies"),
    (r"(?i)^Cargo\.lock$", "rust", "Cargo lock file"),
    (r"(?i)^go\.mod$", "go", "Go module dependencies"),
    (r"(?i)^go\.sum$", "go", "Go module checksums"),
    (r"(?i)^Gemfile$", "ruby", "Ruby dependencies"),
    (r"(?i)^Gemfile\.lock$", "ruby", "Ruby gem lock file"),
    (r"(?i)^composer\.json$", "php", "Composer dependencies"),
    (r"(?i)^composer\.lock$", "php", "Composer lock file"),
    (r"(?i)^pom\.xml$", "java", "Maven dependencies"),
    (r"(?i)^build\.gradle$", "java", "Gradle dependencies"),
    (r"(?i)\.csproj$", "csharp", "NuGet / .NET project"),
    (r"(?i)packages\.config$", "csharp", "NuGet packages"),
];

/// Outdated major versions (heuristic for old packages)
const OUTDATED_VERSION_PATTERNS: &[(&str, i32, &str)] = &[
    // (package_name, outdated_below_major_version, recommendation)
    ("express", 4, "Express.js v3 is very old, upgrade to v4"),
    ("react", 16, "React v15 is EOL, upgrade to v16+"),
    ("react-dom", 16, "React-DOM v15 is EOL, upgrade to v16+"),
    ("angular", 8, "AngularJS (v1.x) is deprecated, consider Angular 2+"),
    ("django", 2, "Django 1.x is EOL, upgrade to Django 2+"),
    ("flask", 1, "Flask 0.x is very old, upgrade to 1+"),
    ("rails", 5, "Rails 4.x is EOL, upgrade to Rails 5+"),
    ("spring", 5, "Spring Framework 4.x is EOL, upgrade to Spring 5+"),
];

#[derive(Debug)]
pub struct DependenciesAnalyzer {
    file_patterns: Vec<(Regex, &'static str, &'static str)>,
    vulnerability_db: HashMap<String, Vec<(String, String, Severity)>>, // package -> [(version, cve, severity)]
    outdated_patterns: Vec<(Regex, i32, &'static str)>,
}

impl DependenciesAnalyzer {
    pub fn new() -> Self {
        let file_patterns: Vec<_> = DEPENDENCY_FILES
            .iter()
            .map(|(pattern, lang, desc)| {
                (
                    Regex::new(pattern).unwrap(),
                    *lang,
                    *desc,
                )
            })
            .collect();

        let mut vulnerability_db = HashMap::new();
        for (pkg, ver, cve, desc, sev) in KNOWN_VULNERABILITIES {
            vulnerability_db
                .entry(pkg.to_string())
                .or_insert_with(Vec::new)
                .push((ver.to_string(), format!("{}: {}", cve, desc), *sev));
        }

        let outdated_patterns: Vec<_> = OUTDATED_VERSION_PATTERNS
            .iter()
            .map(|(pkg, ver, desc)| {
                (
                    Regex::new(&format!(r"(?i)^{}$", regex::escape(pkg))).unwrap(),
                    *ver,
                    *desc,
                )
            })
            .collect();

        Self {
            file_patterns,
            vulnerability_db,
            outdated_patterns,
        }
    }

    fn parse_package_json(&self, content: &str, file: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Ok(value) = serde_json::from_str::<serde_json::Value>(content) {
            // Check dependencies
            if let Some(deps) = value.get("dependencies").and_then(|d| d.as_object()) {
                findings.extend(self.check_npm_packages(deps, file, "dependencies"));
            }
            if let Some(deps) = value.get("devDependencies").and_then(|d| d.as_object()) {
                findings.extend(self.check_npm_packages(deps, file, "devDependencies"));
            }
        }

        findings
    }

    fn check_npm_packages(
        &self,
        deps: &serde_json::Map<String, serde_json::Value>,
        file: &str,
        dep_type: &str,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (pkg, version_val) in deps {
            let version = version_val
                .as_str()
                .unwrap_or("*")
                .trim_start_matches('^')
                .trim_start_matches('~')
                .trim_start_matches(">=")
                .trim_start_matches('=');

            // Check against known vulnerabilities
            if let Some(vulns) = self.vulnerability_db.get(pkg) {
                for (vuln_version, cve_desc, severity) in vulns {
                    if version == *vuln_version || version.starts_with(&format!("{}.", vuln_version)) {
                        findings.push(
                            Finding::new(
                                "DEP-VULN-001",
                                *severity,
                                format!("Vulnerable dependency: {}", cve_desc),
                                Location::new(file),
                                "dependencies",
                            )
                            .with_evidence(format!("{}@{}", pkg, version))
                            .with_remediation(&format!("Upgrade {} to a patched version", pkg))
                        );
                    }
                }
            }

            // Check for outdated major versions
            for (regex, min_major, recommendation) in &self.outdated_patterns {
                if regex.is_match(pkg) {
                    if let Ok(major) = version.split('.').next().unwrap_or("0").parse::<i32>() {
                        if major < *min_major {
                            findings.push(
                                Finding::new(
                                    "DEP-OUTDATED-001",
                                    Severity::Low,
                                    format!("Outdated major version of {}", pkg),
                                    Location::new(file),
                                    "dependencies",
                                )
                                .with_evidence(format!("{}@{}", pkg, version))
                                .with_remediation(*recommendation)
                            );
                        }
                    }
                }
            }
        }

        findings
    }

    fn parse_cargo_toml(&self, content: &str, file: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Simple regex-based parsing for [dependencies] section
        let in_deps = content.contains("[dependencies]") || content.contains("[dev-dependencies]");

        if in_deps {
            for (regex, min_major, recommendation) in &self.outdated_patterns {
                if let Some(mat) = regex.find(content) {
                    // Very basic check - in production would parse TOML properly
                    findings.push(
                        Finding::new(
                            "DEP-INFO-001",
                            Severity::Info,
                            format!("Rust dependencies detected in {}", file),
                            Location::new(file),
                            "dependencies",
                        )
                        .with_remediation("Run `cargo audit` to check for vulnerabilities")
                    );
                    break;
                }
            }
        }

        findings
    }

    fn parse_requirements_txt(&self, content: &str, file: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check for common vulnerable packages in Python
        let vulnerable_python_packages = &[
            ("urllib3", "1.25.10", "CVE-2021-28363", Severity::High),
            ("cryptography", "3.3", "CVE-2020-25659", Severity::Medium),
            ("pillow", "8.2.0", "CVE-2021-34552", Severity::Medium),
        ];

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse package name and version
            if let Some((pkg, version)) = line.split_once("==") {
                let pkg = pkg.trim().to_lowercase();
                let version = version.trim();

                for (vuln_pkg, vuln_ver, cve, severity) in vulnerable_python_packages {
                    if pkg.contains(vuln_pkg) && version == *vuln_ver {
                        findings.push(
                            Finding::new(
                                "DEP-VULN-001",
                                *severity,
                                format!("Vulnerable Python package: {}", cve),
                                Location::new(file),
                                "dependencies",
                            )
                            .with_evidence(format!("{}=={}", pkg, version))
                            .with_remediation(&format!("Upgrade {} to a patched version", pkg))
                        );
                    }
                }
            }
        }

        findings
    }
}

impl Default for DependenciesAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for DependenciesAnalyzer {
    fn name(&self) -> &str {
        "dependencies"
    }

    fn description(&self) -> &str {
        "Checks for known vulnerabilities in dependencies and outdated packages"
    }

    fn analyze(&self, repo: &dyn Repository) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let mut dependency_files_found = Vec::new();

        // First, identify dependency files
        for file_path in repo.files()? {
            let file_str = file_path.to_string_lossy();
            let file_str_ref: &str = file_str.as_ref();

            for (regex, lang, desc) in &self.file_patterns {
                if regex.is_match(file_str_ref) {
                    dependency_files_found.push((file_str_ref.to_string(), *lang));

                    findings.push(
                        Finding::new(
                            "DEP-FILE-001",
                            Severity::Info,
                            format!("{} dependency file", desc),
                            Location::new(file_str_ref),
                            "dependencies",
                        )
                        .with_remediation(&format!(
                            "Consider running a security audit: {}",
                            match *lang {
                                "javascript" => "npm audit",
                                "python" => "pip-audit or safety check",
                                "rust" => "cargo audit",
                                "go" => "govulncheck",
                                _ => "Use appropriate security scanner",
                            }
                        ))
                    );
                }
            }
        }

        // Now analyze each dependency file
        for (file_str, lang) in &dependency_files_found {
            let file_path = std::path::Path::new(file_str);
            match repo.file_content(file_path) {
                Ok(content) => {
                    match *lang {
                        "javascript" => {
                            findings.extend(self.parse_package_json(&content, file_str));
                        }
                        "python" => {
                            findings.extend(self.parse_requirements_txt(&content, file_str));
                        }
                        "rust" => {
                            findings.extend(self.parse_cargo_toml(&content, file_str));
                        }
                        _ => {
                            // For other languages, just add an info finding
                        }
                    }
                }
                Err(_) => continue,
            }
        }

        Ok(findings)
    }
}
