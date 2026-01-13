//! Integration tests for Snitch-Checker analyzers

use snitch_checker::{LocalRepository, Scanner, Severity};

#[test]
fn test_scan_repo_with_secrets() {
    let repo_path = std::path::PathBuf::from("tests/fixtures/repo-with-secrets");
    if !repo_path.exists() {
        return; // Skip if fixtures don't exist in test environment
    }

    let repo = LocalRepository::new(&repo_path).expect("Failed to open test repo");
    let scanner = Scanner::new();
    let report = scanner.scan(&repo).expect("Scan failed");

    // Should find secrets
    assert!(
        report.summary.critical > 0 || report.summary.high > 0,
        "Expected to find secrets in test repo, got {} findings",
        report.summary.total()
    );

    // Check for specific findings
    let has_aws_key = report.findings.iter().any(|f| f.rule_id == "AWS-001" || f.rule_id == "AWS-002");
    assert!(has_aws_key, "Expected to find AWS keys");

    let has_github_token = report.findings.iter().any(|f| f.rule_id.starts_with("GITHUB"));
    assert!(has_github_token, "Expected to find GitHub tokens");

    let has_database_url = report.findings.iter().any(|f| f.rule_id == "DB-001");
    assert!(has_database_url, "Expected to find database URLs");

    println!("Secrets test found {} findings", report.summary.total());
}

#[test]
fn test_scan_repo_with_bad_urls() {
    let repo_path = std::path::PathBuf::from("tests/fixtures/repo-with-bad-urls");
    if !repo_path.exists() {
        return;
    }

    let repo = LocalRepository::new(&repo_path).expect("Failed to open test repo");
    let scanner = Scanner::new();
    let report = scanner.scan(&repo).expect("Scan failed");

    // Should find URL issues
    assert!(
        report.summary.high > 0 || report.summary.medium > 0,
        "Expected to find URL issues in test repo"
    );

    // Check for specific findings
    let has_s3_url = report.findings.iter().any(|f| f.title.contains("S3"));
    assert!(has_s3_url, "Expected to find S3 URL");

    let has_onion = report.findings.iter().any(|f| {
        f.evidence.as_ref().map_or(false, |e| e.contains(".onion"))
    });
    assert!(has_onion, "Expected to find .onion domain");

    println!("URL test found {} findings", report.summary.total());
}

#[test]
fn test_scan_repo_with_file_ops() {
    let repo_path = std::path::PathBuf::from("tests/fixtures/repo-with-file-ops");
    if !repo_path.exists() {
        return;
    }

    let repo = LocalRepository::new(&repo_path).expect("Failed to open test repo");
    let scanner = Scanner::new();
    let report = scanner.scan(&repo).expect("Scan failed");

    // Should find file operation issues
    assert!(
        report.summary.high > 0,
        "Expected to find file operation issues in test repo"
    );

    // Check for specific findings
    let has_eval = report.findings.iter().any(|f| f.rule_id == "FILE-006" || f.title.contains("eval"));
    assert!(has_eval, "Expected to find eval usage");

    let has_pickle = report.findings.iter().any(|f| f.title.contains("pickle"));
    assert!(has_pickle, "Expected to find pickle deserialization");

    println!("File ops test found {} findings", report.summary.total());
}

#[test]
fn test_scan_safe_repo() {
    let repo_path = std::path::PathBuf::from("tests/fixtures/safe-repo");
    if !repo_path.exists() {
        return;
    }

    let repo = LocalRepository::new(&repo_path).expect("Failed to open test repo");
    let scanner = Scanner::new();
    let report = scanner.scan(&repo).expect("Scan failed");

    // Safe repo should have fewer critical/high findings
    let critical_high = report.summary.critical + report.summary.high;

    assert!(
        critical_high < 5,
        "Expected safe repo to have fewer critical/high findings, got {}",
        critical_high
    );

    println!("Safe repo test found {} findings ({} critical/high)",
             report.summary.total(), critical_high);
}

#[test]
fn test_severity_filtering() {
    let repo_path = std::path::PathBuf::from("tests/fixtures/repo-with-secrets");
    if !repo_path.exists() {
        return;
    }

    let repo = LocalRepository::new(&repo_path).expect("Failed to open test repo");
    let scanner = Scanner::new();
    let report = scanner.scan(&repo).expect("Scan failed");

    // Test filtering by severity
    let critical_findings: Vec<_> = report.findings.iter()
        .filter(|f| f.severity >= Severity::Critical)
        .collect();

    let high_and_up: Vec<_> = report.findings.iter()
        .filter(|f| f.severity >= Severity::High)
        .collect();

    assert!(
        critical_findings.len() <= high_and_up.len(),
        "Critical filter should be subset of high filter"
    );

    println!("Severity filtering: {} critical, {} high+",
             critical_findings.len(), high_and_up.len());
}

#[test]
fn test_analyzer_presence() {
    let scanner = Scanner::new();
    let analyzers = scanner.registry().list();

    // Check that all expected analyzers are present
    let analyzer_names: Vec<_> = analyzers.iter().map(|(name, _, _)| name.clone()).collect();

    assert!(analyzer_names.contains(&"secrets".to_string()), "Missing secrets analyzer");
    assert!(analyzer_names.contains(&"url".to_string()), "Missing url analyzer");
    assert!(analyzer_names.contains(&"file-ops".to_string()), "Missing file-ops analyzer");
    assert!(analyzer_names.contains(&"dependencies".to_string()), "Missing dependencies analyzer");

    println!("Found {} analyzers: {:?}", analyzer_names.len(), analyzer_names);
}
