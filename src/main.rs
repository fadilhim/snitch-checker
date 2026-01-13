//! Snitch-Checker: Repository Security Benchmarking Tool
//!
//! A command-line tool that audits local and remote repositories for security vulnerabilities.

mod analyzers;
mod cli;
mod core;
mod git;
mod reporters;
mod utils;

use anyhow::Result;
use cli::Cli;
use clap::Parser;

fn main() -> Result<()> {
    let cli = Cli::parse();

    if let Err(e) = cli.run() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }

    Ok(())
}
