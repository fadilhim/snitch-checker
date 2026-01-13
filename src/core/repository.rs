//! Repository abstraction for Git and local directories

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// Information about a Git commit
#[derive(Debug, Clone)]
pub struct CommitInfo {
    /// Commit hash
    pub hash: String,
    /// Author name
    pub author: String,
    /// Commit message
    pub message: String,
    /// Files changed in this commit
    pub files_changed: Vec<String>,
}

/// Trait for repository operations
pub trait Repository {
    /// Get the repository path
    fn path(&self) -> &Path;

    /// Check if this is a Git repository
    fn is_git_repo(&self) -> bool;

    /// Get all files in the repository (recursively)
    fn files(&self) -> Result<Vec<PathBuf>>;

    /// Get the content of a file
    fn file_content(&self, path: &Path) -> Result<String>;

    /// Get remote URLs (if Git repo)
    fn remote_urls(&self) -> Result<Vec<String>>;

    /// Get commit history (if Git repo)
    fn commit_history(&self) -> Result<Vec<CommitInfo>>;

    /// Get the repository name
    fn name(&self) -> String {
        self.path()
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string()
    }
}

/// A local directory (not necessarily a Git repository)
pub struct LocalRepository {
    path: PathBuf,
}

impl LocalRepository {
    /// Create a new local repository from a path
    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().canonicalize()?;
        if !path.exists() {
            anyhow::bail!("Path does not exist: {}", path.display());
        }
        Ok(Self { path })
    }
}

impl Repository for LocalRepository {
    fn path(&self) -> &Path {
        &self.path
    }

    fn is_git_repo(&self) -> bool {
        self.path.join(".git").exists()
    }

    fn files(&self) -> Result<Vec<PathBuf>> {
        let mut files = Vec::new();
        let mut ignored_dirs = vec![
            ".git",
            "node_modules",
            "target",
            ".venv",
            "venv",
            "__pycache__",
            ".vscode",
            ".idea",
            "dist",
            "build",
        ];

        for entry in walkdir::WalkDir::new(&self.path)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            if path.is_dir() {
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if ignored_dirs.contains(&name) {
                    // Skip this directory
                    continue;
                }
            } else if path.is_file() {
                // Only include text files (simple heuristic)
                if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                    // Common binary extensions to skip
                    if matches!(
                        ext,
                        "exe" | "dll" | "so" | "dylib" | "bin" | "png"
                            | "jpg" | "jpeg" | "gif" | "ico" | "pdf"
                            | "zip" | "tar" | "gz" | "7z" | "woff" | "woff2"
                    ) {
                        continue;
                    }
                }
                if let Ok(rel_path) = path.strip_prefix(&self.path) {
                    files.push(rel_path.to_path_buf());
                }
            }
        }
        Ok(files)
    }

    fn file_content(&self, path: &Path) -> Result<String> {
        let full_path = self.path.join(path);
        std::fs::read_to_string(&full_path)
            .with_context(|| format!("Failed to read file: {}", full_path.display()))
    }

    fn remote_urls(&self) -> Result<Vec<String>> {
        if self.is_git_repo() {
            // Try to use GitRepository for Git-specific features
            if let Ok(git_repo) = GitRepository::new(&self.path) {
                return git_repo.remote_urls();
            }
        }
        Ok(Vec::new())
    }

    fn commit_history(&self) -> Result<Vec<CommitInfo>> {
        if self.is_git_repo() {
            if let Ok(git_repo) = GitRepository::new(&self.path) {
                return git_repo.commit_history();
            }
        }
        Ok(Vec::new())
    }
}

/// A Git repository with Git-specific operations
pub struct GitRepository {
    local: LocalRepository,
    repo: git2::Repository,
}

impl GitRepository {
    /// Open a Git repository at the given path
    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().canonicalize()?;
        let local = LocalRepository::new(&path)?;

        let repo = git2::Repository::discover(&path)
            .with_context(|| format!("Not a Git repository: {}", path.display()))?;

        Ok(Self { local, repo })
    }

    /// Get the origin remote URL
    pub fn origin_url(&self) -> Option<String> {
        self.repo
            .find_remote("origin")
            .ok()
            .and_then(|r| r.url().map(|u| u.to_string()))
    }

    /// Get all remote URLs
    pub fn all_remotes(&self) -> Vec<String> {
        let mut urls = Vec::new();
        if let Ok(remotes) = self.repo.remotes() {
            for remote in remotes.iter().filter_map(|r| r) {
                if let Ok(r) = self.repo.find_remote(remote) {
                    if let Some(url) = r.url() {
                        urls.push(url.to_string());
                    }
                }
            }
        }
        urls
    }

    /// Get the HEAD commit
    pub fn head_commit(&self) -> Option<git2::Commit> {
        self.repo.head().ok()?.peel_to_commit().ok()
    }

    /// Get commit history
    pub fn walk_commits(&self, max_count: usize) -> Vec<CommitInfo> {
        let mut commits = Vec::new();

        if let Some(head) = self.head_commit() {
            let mut revwalk = match self.repo.revwalk() {
                Ok(rw) => rw,
                Err(_) => return commits,
            };

            if revwalk.push(head.id()).is_err() {
                return commits;
            }

            for (i, oid) in revwalk.enumerate() {
                if i >= max_count {
                    break;
                }

                if let Ok(oid) = oid {
                    if let Ok(commit) = self.repo.find_commit(oid) {
                        let author = commit.author();
                        let files_changed = Self::get_files_changed(&self.repo, &commit);

                        commits.push(CommitInfo {
                            hash: oid.to_string(),
                            author: author.name().unwrap_or("Unknown").to_string(),
                            message: commit.message().unwrap_or("").to_string(),
                            files_changed,
                        });
                    }
                }
            }
        }

        commits
    }

    /// Get files changed in a commit
    fn get_files_changed(repo: &git2::Repository, commit: &git2::Commit) -> Vec<String> {
        let mut files = Vec::new();

        if let Ok(tree) = commit.tree() {
            if commit.parent_count() > 0 {
                if let Ok(parent) = commit.parent(0) {
                    if let Ok(parent_tree) = parent.tree() {
                        let diff = match repo.diff_tree_to_tree(
                            Some(&parent_tree),
                            Some(&tree),
                            None,
                        ) {
                            Ok(d) => d,
                            Err(_) => return files,
                        };

                        for delta in diff.deltas() {
                            if let Some(path) = delta.new_file().path() {
                                files.push(path.to_string_lossy().to_string());
                            }
                        }
                    }
                }
            } else {
                // Initial commit - list all files
                tree.walk(git2::TreeWalkMode::PreOrder, |path, _entry| {
                    files.push(path.to_string());
                    git2::TreeWalkResult::Ok
                })
                .ok();
            }
        }

        files
    }
}

impl Repository for GitRepository {
    fn path(&self) -> &Path {
        self.local.path()
    }

    fn is_git_repo(&self) -> bool {
        true
    }

    fn files(&self) -> Result<Vec<PathBuf>> {
        self.local.files()
    }

    fn file_content(&self, path: &Path) -> Result<String> {
        self.local.file_content(path)
    }

    fn remote_urls(&self) -> Result<Vec<String>> {
        Ok(self.all_remotes())
    }

    fn commit_history(&self) -> Result<Vec<CommitInfo>> {
        Ok(self.walk_commits(100)) // Last 100 commits
    }
}

/// Clone a remote repository to a temporary location
pub fn clone_repository(url: &str, dest: &Path) -> Result<GitRepository> {
    let mut callbacks = git2::RemoteCallbacks::new();
    callbacks.credentials(|_url, username_from_url, _allowed_types| {
        git2::Cred::ssh_key_from_agent(
            username_from_url.unwrap_or("git"),
        )
    });

    let mut fetch_options = git2::FetchOptions::new();
    fetch_options.remote_callbacks(callbacks);

    git2::Repository::clone(url, dest)?;

    GitRepository::new(dest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_local_repository() {
        let temp = tempfile::tempdir().unwrap();
        let repo = LocalRepository::new(temp.path()).unwrap();
        assert_eq!(repo.path(), temp.path());
        assert!(!repo.is_git_repo());
    }
}
