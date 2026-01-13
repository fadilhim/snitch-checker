//! Snitch-Checker: Repository Security Benchmarking Tool
//!
//! An interactive CLI tool that audits local and remote repositories for security vulnerabilities.

mod analyzers;
mod cli;
mod core;
mod git;
mod reporters;
mod utils;

use anyhow::{Context, Result};
use console::{style, Color};
use dialoguer::{theme::ColorfulTheme, Confirm, Input, Select};
use indicatif::{ProgressBar, ProgressStyle};
use snitch_checker::{ConsoleReporter, HtmlReporter, LocalRepository, Reporter, Repository, SarifReporter, Scanner};
use std::path::PathBuf;

/// Welcome banner
fn print_banner() {
    println!();
    println!("{}", style("╔════════════════════════════════════════════════════════════╗").fg(Color::Cyan));
    println!("{}", style("║           Snitch-Checker - Repository Security            ║").fg(Color::Cyan));
    println!("{}", style("║                  Security Benchmarking Tool                ║").fg(Color::Cyan));
    println!("{}", style("╚════════════════════════════════════════════════════════════╝").fg(Color::Cyan));
    println!();
}

/// Get scan type selection (local or remote)
fn get_scan_type() -> Result<bool> {
    let items = vec!["Local repository or directory", "Remote Git repository"];
    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("What would you like to scan?")
        .items(&items)
        .default(0)
        .interact()?;

    Ok(selection == 0) // true = local, false = remote
}

/// Get local repository path from user
fn get_local_path() -> Result<String> {
    Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter the path to the repository or directory")
        .validate_with(|input: &String| -> Result<(), &str> {
            if input.trim().is_empty() {
                Err("Path cannot be empty")
            } else {
                Ok(())
            }
        })
        .interact_text()
        .context("Failed to get path input")
}

/// Get remote repository URL from user
fn get_remote_url() -> Result<String> {
    Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter the Git repository URL")
        .with_initial_text("https://github.com/")
        .validate_with(|input: &String| -> Result<(), &str> {
            if input.trim().is_empty() {
                Err("URL cannot be empty")
            } else if !input.contains("github.com") && !input.contains("gitlab.com") && !input.contains("git@") {
                Err("Please enter a valid Git URL (https://github.com/user/repo or git@github.com:user/repo.git)")
            } else {
                Ok(())
            }
        })
        .interact_text()
        .context("Failed to get URL input")
}

/// Clone a remote repository to a temporary directory
fn clone_remote_repo(url: &str) -> Result<String> {
    use std::process::Command;

    let temp_dir = std::env::temp_dir();
    let repo_name = url
        .split('/')
        .last()
        .unwrap_or("repo")
        .replace(".git", "");
    let dest = temp_dir.join(format!("snitch-checker-{}", repo_name));

    // Remove existing directory if it exists
    if dest.exists() {
        std::fs::remove_dir_all(&dest)?;
    }

    let pb = ProgressBar::new(3);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{bar:40.cyan/blue}] {msg}")
        .unwrap());
    pb.set_message("Cloning repository...");
    pb.inc(1);

    let output = Command::new("git")
        .args(["clone", url, dest.to_str().unwrap()])
        .output()
        .context("Failed to clone repository. Make sure git is installed.")?;

    pb.inc(1);

    if !output.status.success() {
        let error = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Failed to clone repository: {}", error);
    }

    pb.finish_with_message("Repository cloned successfully!");
    println!();

    Ok(dest.to_string_lossy().to_string())
}

/// Scan a repository and display results in all formats
fn scan_repository(path: &str) -> Result<()> {
    println!("{}", style("→ Opening repository...").fg(Color::Yellow));

    let repo = LocalRepository::new(path)
        .context("Failed to open repository")?;

    println!("{} {}",
        style("✓").fg(Color::Green),
        style(format!("Repository: {}", repo.name())).fg(Color::White)
    );

    if repo.is_git_repo() {
        println!("{} {}",
            style("✓").fg(Color::Green),
            style("Git repository detected").fg(Color::White)
        );
    }

    println!();
    println!("{}", style("→ Scanning for security vulnerabilities...").fg(Color::Yellow));
    println!();

    let scanner = Scanner::new();
    let report = scanner.scan(&repo)?;

    // Generate output filenames based on repo name and timestamp
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    let repo_name = repo.name().replace(|c: char| !c.is_alphanumeric(), "_");

    let html_path = PathBuf::from(format!("snitch-report-{}-{}.html", repo_name, timestamp));
    let sarif_path = PathBuf::from(format!("snitch-report-{}-{}.sarif", repo_name, timestamp));

    // 1. Generate HTML report
    println!("{}", style("→ Generating HTML report...").fg(Color::Yellow));
    let html_reporter = HtmlReporter::new();
    let html_output = html_reporter.report(&report)?;
    std::fs::write(&html_path, html_output)?;
    println!("{} {}",
        style("✓").fg(Color::Green),
        style(format!("HTML report saved to: {}", html_path.display())).fg(Color::White)
    );

    // 2. Generate SARIF report
    println!("{}", style("→ Generating SARIF report...").fg(Color::Yellow));
    let sarif_reporter = SarifReporter::new();
    let sarif_output = sarif_reporter.report(&report)?;
    std::fs::write(&sarif_path, sarif_output)?;
    println!("{} {}",
        style("✓").fg(Color::Green),
        style(format!("SARIF report saved to: {}", sarif_path.display())).fg(Color::White)
    );

    println!();
    println!("{}", style("════════════════════════════════════════════════════════════════").fg(Color::Cyan));
    println!();

    Ok(())
}

/// Main interactive loop
fn run_interactive() -> Result<()> {
    print_banner();

    loop {
        // Get scan type
        let is_local = get_scan_type()?;
        println!();

        let path = if is_local {
            // Local repository
            let path = get_local_path()?;
            path
        } else {
            // Remote repository
            let url = get_remote_url()?;
            println!();
            clone_remote_repo(&url)?
        };

        println!();

        // Scan the repository
        if let Err(e) = scan_repository(&path) {
            println!();
            println!("{} {}",
                style("✗").fg(Color::Red),
                style(format!("Error during scan: {}", e)).fg(Color::Red)
            );
            println!();
        }

        // Ask if user wants to scan another
        let scan_again = Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Would you like to scan another repository?")
            .default(false)
            .interact()?;

        println!();

        if !scan_again {
            println!("{}", style("Thank you for using Snitch-Checker!").fg(Color::Cyan));
            println!();
            break;
        }

        println!("{}", style("────────────────────────────────────────────────────────────").fg(Color::Cyan));
        println!();
    }

    Ok(())
}

fn main() {
    if let Err(e) = run_interactive() {
        eprintln!("{} {}",
            console::style("Error:").fg(Color::Red).bold(),
            e
        );
        std::process::exit(1);
    }
}
