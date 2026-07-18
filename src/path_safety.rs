use std::path::{Component, Path, PathBuf};

use crate::error::{Error, Result};

/// Safely joins `dest_root` with an archive entry's path.
/// Rejects absolute paths, root/prefix components, and `..`.
pub fn safe_join(dest_root: &Path, entry_path: &Path) -> Result<PathBuf> {
    // Нормализуем разделители Windows-стиля в именах из архива.
    let normalized = entry_path.to_string_lossy().replace('\\', "/");
    let rel = Path::new(&normalized);

    let mut out = dest_root.to_path_buf();
    for comp in rel.components() {
        match comp {
            Component::Normal(part) => out.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(Error::PathTraversal(normalized));
            }
        }
    }
    Ok(out)
}

/// Validate that a symlink placed at `dest_root/link_rel` and pointing to
/// `target` resolves (lexically) to a location inside `dest_root`.
///
/// `safe_join` only protects literal write paths; it does not resolve
/// symlinks. Validating that every created symlink points inside `dest_root`
/// is what prevents a later write from escaping through the link.
///
/// `link_rel` is expected to have already been validated by `safe_join` on the
/// same entry path; callers must run `safe_join` before calling this function.
pub fn safe_symlink_target(_dest_root: &Path, link_rel: &Path, target: &Path) -> Result<()> {
    // Normalize Windows separators in the archive-supplied target.
    let target_norm = target.to_string_lossy().replace('\\', "/");
    let target = Path::new(&target_norm);

    // Absolute targets always escape a relative extraction root.
    if target.is_absolute() {
        return Err(Error::PathTraversal(target_norm));
    }

    // Start from the symlink's PARENT directory (relative to dest_root) and
    // apply the target's components, tracking depth below dest_root.
    // depth must never go negative (that would mean leaving dest_root).
    let mut depth: i64 = 0;
    for comp in link_rel.components() {
        if let Component::Normal(_) = comp {
            depth += 1;
        }
    }
    // The link itself is the last component of link_rel; the target is
    // resolved relative to the link's directory, so drop one level.
    if depth > 0 {
        depth -= 1;
    }

    for comp in target.components() {
        match comp {
            Component::Normal(_) => depth += 1,
            Component::CurDir => {}
            Component::ParentDir => {
                depth -= 1;
                if depth < 0 {
                    return Err(Error::PathTraversal(target_norm));
                }
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(Error::PathTraversal(target_norm));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn normal_relative_path_ok() {
        let r = safe_join(Path::new("/out"), Path::new("a/b/c.txt")).unwrap();
        assert_eq!(r, Path::new("/out/a/b/c.txt"));
    }

    #[test]
    fn parent_traversal_rejected() {
        let e = safe_join(Path::new("/out"), Path::new("../escape")).unwrap_err();
        assert!(matches!(e, crate::Error::PathTraversal(_)));
    }

    #[test]
    fn absolute_path_rejected() {
        let e = safe_join(Path::new("/out"), Path::new("/etc/passwd")).unwrap_err();
        assert!(matches!(e, crate::Error::PathTraversal(_)));
    }

    #[test]
    fn embedded_traversal_rejected() {
        let e = safe_join(Path::new("/out"), Path::new("a/../../b")).unwrap_err();
        assert!(matches!(e, crate::Error::PathTraversal(_)));
    }
}

#[cfg(test)]
mod symlink_tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn relative_target_inside_is_ok() {
        // link at out/sub/link -> ../file  =>  out/file  (inside)
        assert!(
            safe_symlink_target(
                Path::new("/out"),
                Path::new("sub/link"),
                Path::new("../file")
            )
            .is_ok()
        );
    }

    #[test]
    fn same_dir_target_is_ok() {
        assert!(
            safe_symlink_target(Path::new("/out"), Path::new("a/link"), Path::new("sibling"))
                .is_ok()
        );
    }

    #[test]
    fn escaping_relative_target_rejected() {
        // link at out/link -> ../../etc  => escapes /out
        let e = safe_symlink_target(Path::new("/out"), Path::new("link"), Path::new("../../etc"))
            .unwrap_err();
        assert!(matches!(e, crate::Error::PathTraversal(_)));
    }

    #[test]
    fn absolute_target_rejected() {
        let e = safe_symlink_target(
            Path::new("/out"),
            Path::new("link"),
            Path::new("/etc/passwd"),
        )
        .unwrap_err();
        assert!(matches!(e, crate::Error::PathTraversal(_)));
    }

    #[test]
    fn windows_backslash_escape_rejected() {
        let e = safe_symlink_target(Path::new("/out"), Path::new("link"), Path::new("..\\..\\x"))
            .unwrap_err();
        assert!(matches!(e, crate::Error::PathTraversal(_)));
    }
}

#[cfg(test)]
mod edge {
    use super::*;
    use std::path::Path;

    #[test]
    fn windows_backslash_traversal_rejected() {
        let e = safe_join(Path::new("/out"), Path::new("..\\..\\win")).unwrap_err();
        assert!(matches!(e, crate::Error::PathTraversal(_)));
    }

    #[test]
    fn current_dir_components_are_stripped() {
        let r = safe_join(Path::new("/out"), Path::new("./a/./b")).unwrap();
        assert_eq!(r, Path::new("/out/a/b"));
    }

    #[test]
    fn empty_path_yields_root() {
        let r = safe_join(Path::new("/out"), Path::new("")).unwrap();
        assert_eq!(r, Path::new("/out"));
    }
}
