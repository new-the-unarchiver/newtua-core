use std::path::Path;

/// True for macOS sidecar/metadata entries that The Unarchiver hides:
/// any `__MACOSX` path component, a `.DS_Store` file, or an AppleDouble
/// `._name` file.
pub fn is_macos_metadata(path: &Path) -> bool {
    for comp in path.components() {
        if comp.as_os_str() == "__MACOSX" {
            return true;
        }
    }
    match path.file_name().and_then(|s| s.to_str()) {
        Some(name) => name == ".DS_Store" || name.starts_with("._"),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn flags_macos_sidecars() {
        assert!(is_macos_metadata(Path::new("dir/._file.txt")));
        assert!(is_macos_metadata(Path::new(".DS_Store")));
        assert!(is_macos_metadata(Path::new("a/b/.DS_Store")));
        assert!(is_macos_metadata(Path::new("__MACOSX/dir/file")));
        assert!(is_macos_metadata(Path::new("._top")));
    }

    #[test]
    fn keeps_normal_files() {
        assert!(!is_macos_metadata(Path::new("dir/file.txt")));
        assert!(!is_macos_metadata(Path::new("readme.txt")));
        assert!(!is_macos_metadata(Path::new("a._weird"))); // "._" not at name start
        assert!(!is_macos_metadata(Path::new("DS_Store")));
    }
}
