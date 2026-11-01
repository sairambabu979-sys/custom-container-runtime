use std::fmt;

use crate::{Error, Result};

/// A validated container ID.
///
/// The ID becomes a directory name under the state root, so it must not be able to express a
/// path: no `/`, no `..`, no leading `.` or `-`. The allowed alphabet matches runc's.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ContainerId(String);

const MAX_LEN: usize = 1024;

impl ContainerId {
    /// Validate `id`.
    pub fn new(id: &str) -> Result<Self> {
        let invalid = |reason| Error::InvalidId { id: id.to_owned(), reason };
        let mut chars = id.chars();
        match chars.next() {
            None => return Err(invalid("must not be empty")),
            Some(c) if !c.is_ascii_alphanumeric() => {
                return Err(invalid("must start with a letter or digit"));
            }
            Some(_) => {}
        }
        if id.len() > MAX_LEN {
            return Err(invalid("must be at most 1024 characters"));
        }
        if !chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-')) {
            return Err(invalid("may only contain letters, digits, '_', '.' and '-'"));
        }
        Ok(Self(id.to_owned()))
    }

    /// The ID as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ContainerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_reasonable_ids() {
        for id in ["a", "web-1", "db_primary.2", "0abc"] {
            ContainerId::new(id).unwrap();
        }
    }

    #[test]
    fn rejects_anything_path_like() {
        for id in ["", ".", "..", "../etc", "a/b", "-rf", ".hidden", "a b", "é"] {
            assert!(ContainerId::new(id).is_err(), "{id:?} should be rejected");
        }
        assert!(ContainerId::new(&"a".repeat(1025)).is_err());
    }
}
