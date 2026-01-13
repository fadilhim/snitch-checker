//! Git repository operations

use crate::core::GitRepository;
use anyhow::Result;
use std::path::Path;

/// Clone a remote repository to a local directory
pub fn clone_repository(url: &str, dest: &Path) -> Result<GitRepository> {
    // Create the parent directory if it doesn't exist
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Clone using git2
    let mut callbacks = git2::RemoteCallbacks::new();
    callbacks.credentials(|_url, username_from_url, _allowed_types| {
        git2::Cred::ssh_key_from_agent(username_from_url.unwrap_or("git"))
    });

    let mut fetch_options = git2::FetchOptions::new();
    fetch_options.remote_callbacks(callbacks);

    // Try to clone
    git2::Repository::clone(url, dest)?;

    // Open the cloned repository
    GitRepository::new(dest)
}
