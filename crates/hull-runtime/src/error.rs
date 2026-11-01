use std::fmt::Write as _;
use std::io;

use crate::sync::Stage;

/// Everything that can go wrong in the runtime.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The container ID is not acceptable.
    #[error("invalid container id {id:?}: {reason}")]
    InvalidId {
        /// The rejected ID.
        id: String,
        /// Why it was rejected.
        reason: &'static str,
    },
    /// A container with this ID is already known.
    #[error("container {0:?} already exists")]
    AlreadyExists(String),
    /// No container with this ID is known.
    #[error("container {0:?} does not exist")]
    NotFound(String),
    /// Another runtime process is operating on the container.
    #[error("container {0:?} is busy: another hull-runtime process holds its lock")]
    Locked(String),
    /// `config.json` could not be loaded.
    #[error(transparent)]
    Load(#[from] hull_spec::LoadError),
    /// `config.json` failed validation.
    #[error(transparent)]
    Invalid(#[from] hull_spec::ValidationErrors),
    /// The container's init process reported a failure.
    #[error("container init failed during {stage}: {message}")]
    Init {
        /// What the init process was doing.
        stage: Stage,
        /// The full error chain, rendered inside the container.
        message: String,
        /// The exit code to use, if the failure maps to one (126/127 for exec failures).
        exit_code: Option<i32>,
    },
    /// The init process disappeared without explaining why.
    #[error("container init exited during setup without reporting an error ({0})")]
    InitVanished(String),
    /// The requested operation is not supported (yet).
    #[error("{0}")]
    Unsupported(String),
    /// A system call or I/O operation failed.
    #[error("{context}")]
    Io {
        /// What we were trying to do, including the paths involved.
        context: String,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
}

/// Shorthand used throughout the crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Attach a description of the failed operation to an I/O error.
///
/// Errors without context are what make container runtimes miserable to debug: "permission
/// denied" with no path. Every fallible syscall in hull goes through this.
pub(crate) trait Context<T> {
    fn context(self, context: impl FnOnce() -> String) -> Result<T>;
}

impl<T, E: Into<io::Error>> Context<T> for std::result::Result<T, E> {
    fn context(self, context: impl FnOnce() -> String) -> Result<T> {
        self.map_err(|e| Error::Io { context: context(), source: e.into() })
    }
}

/// Render an error and all of its sources as `outer: inner: innermost`.
pub fn render_chain(error: &dyn std::error::Error) -> String {
    let mut out = error.to_string();
    let mut source = error.source();
    while let Some(e) = source {
        let _ = write!(out, ": {e}");
        source = e.source();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_context_and_errno() {
        let err: Result<()> = Err(io::Error::from_raw_os_error(2)).context(|| "open /x".into());
        let rendered = render_chain(&err.unwrap_err());
        assert!(rendered.starts_with("open /x: "), "{rendered}");
        assert!(rendered.contains("No such file"), "{rendered}");
    }
}
