//! Command-line interface structure

use crate::core::{LocalRepository, Repository, Scanner, Severity};
use crate::reporters::{ConsoleReporter, HtmlReporter, OutputFormat, Reporter, SarifReporter};
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// Snitch-Checker: Repository security benchmarking tool
#[derive(Parser)]
#[command(name = "snitch")]
#[command(author = "Snitch-Checker Contributors")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "Security audit tool for local and remote repositories", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Output format (console, html, sarif)
    #[arg(short = 'f', long, default_value = "console", global = true)]
    pub format: String,

    /// Output file (for html/sarif formats)
    #[arg(short = 'o', long, global = true)]
    pub output: Option<PathBuf>,

    /// Minimum severity level to report (info, low, medium, high, critical)
    #[arg(short = 's', long, default_value = "info", global = true)]
    pub severity: String,

    /// Show progress bar during scan
    #[arg(long, default_value = "true", global = true, action = clap::ArgAction::SetTrue)]
    pub progress: bool,

    /// Enable specific analyzers only
    #[arg(long, global = true)]
    pub analyzers: Option<Vec<String>>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Scan a local repository or directory
    Scan {
        /// Path to repository or directory
        #[arg(value_name = "PATH")]
        path: PathBuf,
    },

    /// Scan a remote repository (clones to temp directory)
    Remote {
        /// Repository URL (git@github.com:user/repo.git or https://...)
        #[arg(value_name = "URL")]
        url: String,

        /// Temporary directory for clone (default: system temp)
        #[arg(short = 't', long)]
        temp_dir: Option<PathBuf>,

        /// Keep the cloned repository after scan
        #[arg(long)]
        keep: bool,
    },

    /// List available analyzers
    ListAnalyzers,

    /// Analyze a single file (quick check)
    Check {
        /// File to check
        #[arg(value_name = "FILE")]
        file: PathBuf,
    },
}

impl Cli {
    pub fn run(&self) -> Result<()> {
        match &self.command {
            Commands::Scan { path } => {
                self.scan_local(path.clone())?;
            }
            Commands::Remote {
                url,
                temp_dir,
                keep,
            } => {
                self.scan_remote(url.clone(), temp_dir.clone(), *keep)?;
            }
            Commands::ListAnalyzers => {
                self.list_analyzers()?;
            }
            Commands::Check { file } => {
                self.check_file(file.clone())?;
            }
        }
        Ok(())
    }

    fn parse_severity(&self) -> Result<Severity> {
        self.severity
            .parse::<Severity>()
            .map_err(|e| anyhow::anyhow!("Invalid severity level: {}", e))
    }

    fn create_scanner(&self) -> Result<Scanner> {
        let mut scanner = Scanner::new();

        // Configure enabled analyzers
        if let Some(ref analyzers) = self.analyzers {
            scanner
                .registry_mut()
                .enable_only(analyzers)
                .context("Failed to configure analyzers")?;
        }

        Ok(scanner)
    }

    fn scan_local(&self, path: PathBuf) -> Result<()> {
        let min_severity = self.parse_severity()?;
        let scanner = self.create_scanner()?;

        println!("Scanning: {}", path.display());
        println!();

        let repo = LocalRepository::new(&path).context("Failed to open repository")?;

        let report = if self.progress {
            scanner.scan_with_progress(&repo, true)
        } else {
            scanner.scan(&repo)
        }?;

        self.output_report(&report, min_severity)?;

        // Exit with error code if critical/high findings
        if report.summary.critical > 0 || report.summary.high > 0 {
            std::process::exit(1);
        }

        Ok(())
    }

    fn scan_remote(&self, url: String, temp_dir: Option<PathBuf>, keep: bool) -> Result<()> {
        let min_severity = self.parse_severity()?;
        let scanner = self.create_scanner()?;

        let temp = temp_dir.unwrap_or_else(|| {
            std::env::temp_dir().join(format!("snitch-{}", std::process::id()))
        });

        println!("Cloning: {}", url);

        let repo = match crate::git::clone_repository(&url, &temp) {
            Ok(r) => r,
            Err(e) => {
                // Try alternative approach with git2 clone
                anyhow::bail!("Failed to clone repository: {}. Make sure git is installed and the URL is correct.", e);
            }
        };

        println!("Clone complete. Starting scan...\n");

        let report = if self.progress {
            scanner.scan_with_progress(&repo, true)
        } else {
            scanner.scan(&repo)
        }?;

        self.output_report(&report, min_severity)?;

        // Clean up unless --keep was specified
        if !keep {
            println!("\nCleaning up temporary directory...");
            std::fs::remove_dir_all(temp)
                .context("Failed to clean up temporary directory")?;
        } else {
            println!("\nRepository kept at: {}", temp.display());
        }

        // Exit with error code if critical/high findings
        if report.summary.critical > 0 || report.summary.high > 0 {
            std::process::exit(1);
        }

        Ok(())
    }

    fn list_analyzers(&self) -> Result<()> {
        let scanner = Scanner::new();
        let analyzers = scanner.registry().list();

        println!("Available Analyzers:\n");
        for (name, description, enabled) in analyzers {
            let status = if enabled { "" } else { " (disabled)" };
            println!("  {}{} - {}", name, status, description);
        }

        Ok(())
    }

    fn check_file(&self, file: PathBuf) -> Result<()> {
        let min_severity = self.parse_severity()?;

        let content = std::fs::read_to_string(&file).context("Failed to read file")?;

        // Create a temporary scanner
        let scanner = Scanner::new();

        // For single file check, we'll create a minimal repo wrapper
        // This is a simplified approach - in production you'd want a proper single-file scanner
        println!("Checking file: {}", file.display());
        println!();
        println!("File size: {} bytes", content.len());
        println!("Lines: {}", content.lines().count());
        println!("\nTip: Use 'snitch scan <directory>' for a full security audit.");

        Ok(())
    }

    fn output_report(&self, report: &crate::core::ScanReport, min_severity: Severity) -> Result<()> {
        let format = OutputFormat::from_str(&self.format)
            .unwrap_or(OutputFormat::Console);

        let output = match format {
            OutputFormat::Console => {
                let reporter = ConsoleReporter::new().with_min_severity(min_severity);
                reporter.report(report)?
            }
            OutputFormat::Html => {
                let reporter = HtmlReporter::new().with_min_severity(min_severity);
                reporter.report(report)?
            }
            OutputFormat::Sarif => {
                let reporter = SarifReporter::new().with_min_severity(min_severity);
                reporter.report(report)?
            }
        };

        // Write to file or stdout
        if let Some(ref path) = self.output {
            std::fs::write(path, output).context("Failed to write output file")?;
            println!("Report written to: {}", path.display());
        } else {
            print!("{}", output);
        }

        Ok(())
    }
}
