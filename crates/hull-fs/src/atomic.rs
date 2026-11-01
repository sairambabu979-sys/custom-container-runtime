use std::io::{self, Write};
use std::path::Path;

/// Replace `dir/name` with `data` so that readers see either the old or the new content, never a
/// mix, even if the process crashes or the machine loses power halfway through.
///
/// The sequence is: write a temporary file in the same directory, `fsync` it, `rename` it over the
/// target (atomic within one filesystem), then `fsync` the directory so the rename itself is
/// durable.
pub fn atomic_write(dir: &Path, name: &str, data: &[u8]) -> io::Result<()> {
    let tmp_name = format!(".{name}.tmp.{}", std::process::id());
    let tmp_path = dir.join(&tmp_name);
    let result = (|| {
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&tmp_path)?;
        file.write_all(data)?;
        file.sync_all()?;
        std::fs::rename(&tmp_path, dir.join(name))?;
        std::fs::File::open(dir)?.sync_all()
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_content_and_leaves_no_temp_files() {
        let dir = tempfile::tempdir().unwrap();
        atomic_write(dir.path(), "state.json", b"one").unwrap();
        atomic_write(dir.path(), "state.json", b"two").unwrap();
        assert_eq!(std::fs::read(dir.path().join("state.json")).unwrap(), b"two");
        let entries: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
        assert_eq!(entries.len(), 1);
    }
}
