//! File utility functions

use std::path::Path;

/// Check if a file is likely binary based on its extension
pub fn is_binary_file(path: &Path) -> bool {
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        let ext_lower = ext.to_lowercase();
        return matches!(
            ext_lower.as_str(),
            "exe" | "dll" | "so" | "dylib" | "bin" | "png" | "jpg"
                | "jpeg" | "gif" | "ico" | "pdf" | "zip" | "tar"
                | "gz" | "7z" | "rar" | "bz2" | "xz" | "woff"
                | "woff2" | "ttf" | "eot" | "mp3" | "mp4" | "avi"
                | "mov" | "wmv" | "flv" | "mkv" | "class" | "jar"
                | "war" | "ear" | "so" | "a" | "lib" | "obj" | "o"
        );
    }
    false
}

/// Check if a directory should be ignored
pub fn is_ignored_dir(name: &str) -> bool {
    matches!(
        name,
        ".git"
            | ".svn"
            | ".hg"
            | "node_modules"
            | "target"
            | "build"
            | "dist"
            | ".venv"
            | "venv"
            | ".virtualenv"
            | "__pycache__"
            | ".pytest_cache"
            | ".vscode"
            | ".idea"
            | ".vs"
            | "vendor"
            | "third_party"
            | ".bundle"
            | "tmp"
            | "temp"
            | ".gradle"
            | "gradle"
            | ".maven"
            | "maven"
    )
}

/// Check if a file is likely to be a dependency/lock file
pub fn is_dependency_file(path: &Path) -> bool {
    if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
        let lower = file_name.to_lowercase();
        return matches!(
            lower.as_str(),
            "package-lock.json" | "yarn.lock" | "pnpm-lock.yaml"
                | "cargo.lock" | "go.sum" | "pom.xml"
                | "build.gradle" | "gradle.lock"
                | "gemfile.lock" | "composer.lock"
                | "packages.lock.json" | "poetry.lock"
        );
    }
    false
}

/// Get file extension as lowercase string
pub fn get_extension(path: &Path) -> Option<String> {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_lowercase())
}

/// Check if a file is a text file based on common text extensions
pub fn is_text_file(path: &Path) -> bool {
    if let Some(ext) = get_extension(path) {
        return matches!(
            ext.as_str(),
            "txt" | "md" | "rst" | "adoc" | "json" | "yaml"
                | "yml" | "toml" | "xml" | "html" | "htm"
                | "css" | "scss" | "sass" | "less" | "js"
                | "jsx" | "ts" | "tsx" | "py" | "rs" | "go"
                | "java" | "kt" | "kts" | "c" | "h" | "cpp"
                | "hpp" | "cc" | "cxx" | "cs" | "php" | "rb"
                | "sh" | "bash" | "zsh" | "fish" | "ps1" | "psm1"
                | "sql" | "graphql" | "gql" | "wsdl" | "xsd"
                | "dtd" | "xslt" | "svg" | "vue" | "svelte"
                | "astro" | "elm" | "dart" | "lua" | "r" | "rmd"
                | "jl" | "nim" | "v" | "zig" | "cr" | "ex"
                | "exs" | "erl" | "hs" | "lhs" | "fs" | "fsi"
                | "fsx" | "ml" | "mli" | "lisp" | "lsp" | "scm"
                | "rkt" | "clj" | "cljs" | "cljc" | "edn" | "lua"
                | "pl" | "pm" | "t" | "pod" | "rs"
        );
    }
    // If no extension, assume it could be text (e.g., Makefile, Dockerfile)
    true
}
