use std::path::{Component, Path, PathBuf};

use crate::error::{Error, Result};

/// Безопасно соединяет `dest_root` с путём записи из архива.
/// Отклоняет абсолютные пути, корневые/префиксные компоненты и `..`.
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
        assert!(safe_symlink_target(Path::new("/out"), Path::new("sub/link"), Path::new("../file")).is_ok());
    }

    #[test]
    fn same_dir_target_is_ok() {
        assert!(safe_symlink_target(Path::new("/out"), Path::new("a/link"), Path::new("sibling")).is_ok());
    }

    #[test]
    fn escaping_relative_target_rejected() {
        // link at out/link -> ../../etc  => escapes /out
        let e = safe_symlink_target(Path::new("/out"), Path::new("link"), Path::new("../../etc")).unwrap_err();
        assert!(matches!(e, crate::Error::PathTraversal(_)));
    }

    #[test]
    fn absolute_target_rejected() {
        let e = safe_symlink_target(Path::new("/out"), Path::new("link"), Path::new("/etc/passwd")).unwrap_err();
        assert!(matches!(e, crate::Error::PathTraversal(_)));
    }

    #[test]
    fn windows_backslash_escape_rejected() {
        let e = safe_symlink_target(Path::new("/out"), Path::new("link"), Path::new("..\\..\\x")).unwrap_err();
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
