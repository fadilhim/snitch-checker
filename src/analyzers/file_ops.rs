//! File operations auditing

use crate::analyzers::Analyzer;
use crate::core::{Finding, Location, Repository, Severity};
use anyhow::Result;
use regex::Regex;

/// Dangerous file operation patterns
const DANGEROUS_FILE_PATTERNS: &[(&str, &str, &str, Severity)] = &[
    // Path traversal patterns
    (
        r"(?i)\.\.\/",
        "FILE-001",
        "Path traversal pattern detected (../)",
        Severity::Medium,
    ),
    (
        r"(?i)%2e%2e",
        "FILE-002",
        "URL-encoded path traversal pattern",
        Severity::Medium,
    ),
    (
        r"(?i)\.\.\\",
        "FILE-003",
        "Windows path traversal pattern detected (..\\)",
        Severity::Medium,
    ),
    // Temp file usage
    (
        r"(?i)/tmp/",
        "FILE-004",
        "Usage of /tmp directory (may have security implications)",
        Severity::Low,
    ),
    (
        r"(?i)%TEMP%|\\Temp\\",
        "FILE-005",
        "Usage of Windows temp directory",
        Severity::Low,
    ),
    // Dangerous file operations
    (
        r"(?i)\.exec\(|\.eval\(|eval\s*\(",
        "FILE-006",
        "Use of eval/exec functions (code injection risk)",
        Severity::High,
    ),
    (
        r"(?i)exec\s*\(|system\s*\(|popen\s*\(",
        "FILE-007",
        "Use of system/shell execution functions",
        Severity::High,
    ),
    (
        r"(?i)spawn\s*\(|child_process",
        "FILE-008",
        "Use of child process spawning (command injection risk)",
        Severity::Medium,
    ),
    // File inclusion patterns
    (
        r"(?i)include\s*\(|require\s*\(",
        "FILE-009",
        "Dynamic file inclusion (may lead to remote file inclusion)",
        Severity::Medium,
    ),
    (
        r"(?i)file_get_contents\s*\(|file_put_contents\s*\(",
        "FILE-010",
        "Use of file_get_contents/put_contents (may be unsafe with user input)",
        Severity::Medium,
    ),
    // Serialization/Pickling
    (
        r"(?i)pickle\.load|unpickle",
        "FILE-011",
        "Use of pickle deserialization (can execute arbitrary code)",
        Severity::High,
    ),
    (
        r"(?i)yaml\.load\(.*\)",
        "FILE-012",
        "Unsafe YAML loading (may execute arbitrary code)",
        Severity::High,
    ),
    // Hardcoded permissions
    (
        r"(?i)0777|0x1ff|777",
        "FILE-013",
        "World-writable file permissions (777)",
        Severity::Medium,
    ),
    (
        r"(?i)chmod\s*\([^)]*0777",
        "FILE-014",
        "chmod with 777 permissions (world-writable)",
        Severity::Medium,
    ),
];

/// Suspicious file access patterns in different languages
const LANGUAGE_SPECIFIC: &[(&str, &str, &str, Severity)] = &[
    // Python
    (
        r#"(?i)open\s*\(\s*['\"]\w+\s*\+\s*"#,
        "python",
        "Dynamic file path construction (path traversal risk)",
        Severity::High,
    ),
    (
        r"(?i)subprocess\.(call|run|Popen)\s*\(\s*shell\s*=\s*True",
        "python",
        "Subprocess with shell=True (command injection risk)",
        Severity::High,
    ),
    // JavaScript/TypeScript
    (
        r"(?i)fs\.(readFile|writeFile|unlink)\s*\(\s*[^,]*\s*\+",
        "javascript",
        "Dynamic file path construction in fs operations",
        Severity::High,
    ),
    (
        r"(?i)require\s*\(\s*[^)]*\+",
        "javascript",
        "Dynamic require() (code injection risk)",
        Severity::High,
    ),
    (
        r"(?i)child_process\.(exec|spawn)\s*\(",
        "javascript",
        "Use of child_process (command injection risk)",
        Severity::Medium,
    ),
    // PHP
    (
        r"(?i)\$_(GET|POST|REQUEST)\[[^\]]+\]\s*\)\s*\);",
        "php",
        "Direct use of user input in file operations",
        Severity::High,
    ),
    (
        r"(?i)unserialize\s*\(",
        "php",
        "Use of unserialize (object injection risk)",
        Severity::High,
    ),
    // Java
    (
        r"(?i)Runtime\.getRuntime\(\)\.exec\s*\(",
        "java",
        "Use of Runtime.exec() (command injection risk)",
        Severity::High,
    ),
    (
        r"(?i)ObjectInputStream\.readObject\s*\(",
        "java",
        "Use of ObjectInputStream (deserialization risk)",
        Severity::Medium,
    ),
    // Go
    (
        r"(?i)exec\.Command\s*\([^,]*\+",
        "go",
        "Dynamic command construction (command injection risk)",
        Severity::High,
    ),
];

/// Files that should be flagged for review
const SUSPICIOUS_FILE_EXTENSIONS: &[(&str, &str, Severity)] = &[
    (".bak", "Backup file (may contain sensitive data)", Severity::Low),
    (".backup", "Backup file (may contain sensitive data)", Severity::Low),
    (".old", "Old version of file", Severity::Info),
    (".tmp", "Temporary file", Severity::Info),
    (".swp", "Vim swap file (may contain unsaved changes)", Severity::Low),
    (".swo", "Vim swap file", Severity::Low),
    (".~", "Backup file", Severity::Info),
    (".log", "Log file (may contain sensitive information)", Severity::Low),
    (".cache", "Cache file", Severity::Info),
];

#[derive(Debug)]
pub struct FileOpsAnalyzer {
    patterns: Vec<(Regex, &'static str, &'static str, Severity)>,
    lang_patterns: Vec<(Regex, &'static str, &'static str, Severity)>,
    extension_patterns: Vec<(Regex, &'static str, Severity)>,
}

impl FileOpsAnalyzer {
    pub fn new() -> Self {
        let patterns: Vec<_> = DANGEROUS_FILE_PATTERNS
            .iter()
            .map(|(pattern, id, desc, sev)| {
                (
                    Regex::new(pattern).unwrap_or_else(|_| {
                        panic!("Invalid file pattern: {}", pattern)
                    }),
                    *id,
                    *desc,
                    *sev,
                )
            })
            .collect();

        let lang_patterns: Vec<_> = LANGUAGE_SPECIFIC
            .iter()
            .map(|(pattern, lang, desc, sev)| {
                (
                    Regex::new(pattern).unwrap_or_else(|_| {
                        panic!("Invalid language pattern: {}", pattern)
                    }),
                    *lang,
                    *desc,
                    *sev,
                )
            })
            .collect();

        let extension_patterns: Vec<_> = SUSPICIOUS_FILE_EXTENSIONS
            .iter()
            .map(|(ext, desc, sev)| {
                (
                    Regex::new(&format!(r"{}$", regex::escape(ext))).unwrap(),
                    *desc,
                    *sev,
                )
            })
            .collect();

        Self {
            patterns,
            lang_patterns,
            extension_patterns,
        }
    }

    fn detect_language(file: &str) -> Option<&'static str> {
        let ext = std::path::Path::new(file)
            .extension()
            .and_then(|e| e.to_str())?;

        match ext {
            "py" | "pyw" => Some("python"),
            "js" | "ts" | "jsx" | "tsx" => Some("javascript"),
            "php" => Some("php"),
            "java" | "jar" => Some("java"),
            "go" => Some("go"),
            "rs" => Some("rust"),
            "rb" => Some("ruby"),
            "cs" => Some("csharp"),
            _ => None,
        }
    }

    fn scan_content(&self, content: &str, file: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = content.lines().collect();
        let language = Self::detect_language(file);

        for (line_idx, line) in lines.iter().enumerate() {
            // Check general dangerous patterns
            for (regex, rule_id, desc, severity) in &self.patterns {
                for mat in regex.find_iter(line) {
                    let location = Location::new(file)
                        .with_line(line_idx)
                        .with_column(mat.start());

                    findings.push(
                        Finding::new(
                            *rule_id,
                            *severity,
                            *desc,
                            location,
                            "file-ops",
                        )
                        .with_evidence(mat.as_str().to_string())
                    );
                }
            }

            // Check language-specific patterns
            if let Some(lang) = language {
                for (regex, detected_lang, desc, severity) in &self.lang_patterns {
                    if *detected_lang == lang || (*detected_lang == "javascript" && lang == "typescript") {
                        for mat in regex.find_iter(line) {
                            let location = Location::new(file)
                                .with_line(line_idx)
                                .with_column(mat.start());

                            findings.push(
                                Finding::new(
                                    "FILE-LANG-001",
                                    *severity,
                                    (*desc).to_string(),
                                    location,
                                    "file-ops",
                                )
                                .with_evidence(mat.as_str().to_string())
                            );
                        }
                    }
                }
            }
        }

        findings
    }
}

impl Default for FileOpsAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for FileOpsAnalyzer {
    fn name(&self) -> &str {
        "file-ops"
    }

    fn description(&self) -> &str {
        "Audits file operations for dangerous patterns (path traversal, code injection, etc.)"
    }

    fn analyze(&self, repo: &dyn Repository) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // First, check for suspicious file extensions
        for file_path in repo.files()? {
            let file_str = file_path.to_string_lossy();
            let file_str_ref: &str = file_str.as_ref();

            for (regex, desc, severity) in &self.extension_patterns {
                if regex.is_match(file_str_ref) {
                    findings.push(
                        Finding::new(
                            "FILE-EXT-001",
                            *severity,
                            (*desc).to_string(),
                            Location::new(file_str_ref),
                            "file-ops",
                        )
                        .with_remediation("Consider whether this file should be in version control")
                    );
                }
            }

            // Then scan file content
            match repo.file_content(&file_path) {
                Ok(content) => {
                    findings.extend(self.scan_content(&content, file_str_ref));
                }
                Err(_) => continue,
            }
        }

        Ok(findings)
    }
}
