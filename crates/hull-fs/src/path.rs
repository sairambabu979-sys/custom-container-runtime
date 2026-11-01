use std::path::{Component, Path, PathBuf};

/// Lexically normalize `path` into an absolute path with no `.`, `..` or repeated separators.
///
/// `..` at the root stays at the root, so `"/../../etc"` becomes `"/etc"`. Relative input is
/// treated as relative to `/`.
///
/// This is purely textual. It does **not** resolve symlinks, and it is not a security boundary on
/// its own: [`crate::SafeRoot`] is. It exists so that paths are canonical in error messages and so
/// that component-by-component directory creation never sees `..`.
pub fn clean_absolute(path: &Path) -> PathBuf {
    let mut parts: Vec<&std::ffi::OsStr> = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(name) => parts.push(name),
            Component::ParentDir => {
                parts.pop();
            }
            Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
        }
    }
    let mut out = PathBuf::from("/");
    out.extend(parts);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes() {
        let cases = [
            ("/", "/"),
            ("", "/"),
            ("/etc/", "/etc"),
            ("etc/passwd", "/etc/passwd"),
            ("/a/./b//c", "/a/b/c"),
            ("/a/b/../c", "/a/c"),
            ("/../../etc", "/etc"),
            ("/a/../../..", "/"),
        ];
        for (input, want) in cases {
            assert_eq!(clean_absolute(Path::new(input)), Path::new(want), "input {input:?}");
        }
    }
}
