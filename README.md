# Snitch-Checker

A **repository security benchmarking tool** that scans local and remote Git repositories for security vulnerabilities.

## Features

- **Secret Scanning** - Detects hardcoded API keys, tokens, credentials, and private keys
- **URL Analysis** - Identifies suspicious URLs, hardcoded endpoints, and insecure protocols
- **File Operations Audit** - Finds dangerous file operations like path traversal and code injection risks
- **Dependency Scanning** - Checks for known vulnerabilities in project dependencies
- **Multiple Output Formats** - Console, HTML reports, and SARIF for CI/CD integration

## Installation

```bash
# Build from source
cargo build --release

# The binary will be at target/release/snitch.exe (Windows) or target/release/snitch (Linux/Mac)
```

## Usage

### Scan a Local Repository

```bash
snitch scan ./my-project
```

### Scan a Remote Repository

```bash
snitch remote https://github.com/user/repo.git
```

### Generate Reports

```bash
# HTML report
snitch scan ./my-project --format html --output report.html

# SARIF (for CI/CD)
snitch scan ./my-project --format sarif --output results.sarif
```

### Filter by Severity

```bash
# Only show high and critical issues
snitch scan ./my-project --severity high
```

### Use Specific Analyzers

```bash
# Only run secrets and URL scanners
snitch scan ./my-project --analyzers secrets urls
```

## Output

### Console Output

```
Snitch Security Scan Report
──────────────────────────────────────────────────────────────────────

Repository: ./my-project
Scan Time: 2025-01-13 14:30:00 UTC
Duration: 2.45s

Summary
  Critical: 3
  High: 7
  Medium: 12
  Low: 5
  Info: 8
  Total: 35

[CRITICAL] AWS Access Key detected
  Rule: AWS-001
  Location: src/config.rs:42
  Description: AWS Access Key ID detected
  Evidence: AKIAIOSFODNN7EXAMPLE
  Remediation: Remove credentials from code and use environment variables
```

### HTML Report

Interactive HTML report with filtering by severity, code snippets, and remediation guidance.

## Analyzers

| Analyzer | Description |
|----------|-------------|
| `secrets` | Scans for hardcoded secrets, credentials, and private keys |
| `url` | Detects suspicious URLs, connection strings, and hardcoded endpoints |
| `file-ops` | Audits file operations for dangerous patterns |
| `dependencies` | Checks for known vulnerabilities in dependencies |

List all analyzers:
```bash
snitch list-analyzers
```

## Development

```bash
# Run tests
cargo test

# Format code
cargo fmt

# Lint
cargo clippy

# Build with debug output
RUST_LOG=debug cargo run -- scan ./test-project
```

## License

MIT
