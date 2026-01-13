//! Regex pattern utilities

use regex::Regex;

/// Common patterns used across analyzers
pub struct Patterns;

impl Patterns {
    /// Email address pattern
    pub fn email() -> Regex {
        Regex::new(
            r"(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b"
        ).unwrap()
    }

    /// IPv4 address pattern
    pub fn ipv4() -> Regex {
        Regex::new(
            r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
        ).unwrap()
    }

    /// UUID pattern
    pub fn uuid() -> Regex {
        Regex::new(
            r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"
        ).unwrap()
    }

    /// Base64 encoded string pattern (20+ chars)
    pub fn base64() -> Regex {
        Regex::new(
            r"[A-Za-z0-9+/]{20,}={0,2}"
        ).unwrap()
    }

    /// Hex string pattern (16+ chars)
    pub fn hex() -> Regex {
        Regex::new(
            r"(?i)[0-9a-f]{16,}"
        ).unwrap()
    }

    /// HTTP/HTTPS URL pattern
    pub fn url() -> Regex {
        Regex::new(
            r#"(?i)https?://[^\s\"'<>]+"#
        ).unwrap()
    }
}
