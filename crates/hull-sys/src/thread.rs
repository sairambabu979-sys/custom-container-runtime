//! Thread-count checks.
//!
//! A fork-like `clone3` copies only the calling thread. If any other thread held a lock (inside
//! `malloc`, inside a logger, anywhere), the child inherits that lock in its locked state, and the
//! thread that would have released it does not exist in the child. The child then deadlocks the
//! first time it touches that lock.
//!
//! The kernel adds a second, independent rule: `setns(CLONE_NEWUSER)` and `unshare(CLONE_NEWUSER)`
//! fail with `EINVAL` in a multi-threaded process.
//!
//! Both rules are why `hull-runtime` is single-threaded, and why [`ensure_single_threaded`] runs
//! before every `clone3`. This is also the reason the runtime is not written in Go: the Go runtime
//! always starts several threads before `main` runs.

use std::{fmt, io};

/// Count the threads of the current process by listing `/proc/self/task`.
pub fn thread_count() -> io::Result<usize> {
    let mut count = 0;
    for entry in std::fs::read_dir("/proc/self/task")? {
        entry?;
        count += 1;
    }
    Ok(count)
}

/// Error returned by [`ensure_single_threaded`].
#[derive(Debug)]
pub enum ThreadCheckError {
    /// The process has more than one thread.
    MultiThreaded(usize),
    /// `/proc/self/task` could not be read.
    Io(io::Error),
}

impl fmt::Display for ThreadCheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MultiThreaded(n) => write!(
                f,
                "process has {n} threads, but namespace operations require exactly one \
                 (a dependency probably spawned a background thread)"
            ),
            Self::Io(e) => write!(f, "cannot count threads via /proc/self/task: {e}"),
        }
    }
}

impl std::error::Error for ThreadCheckError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::MultiThreaded(_) => None,
            Self::Io(e) => Some(e),
        }
    }
}

/// Fail unless the calling process has exactly one thread.
pub fn ensure_single_threaded() -> Result<(), ThreadCheckError> {
    match thread_count() {
        Ok(1) => Ok(()),
        Ok(n) => Err(ThreadCheckError::MultiThreaded(n)),
        Err(e) => Err(ThreadCheckError::Io(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_a_second_thread() {
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let handle = std::thread::spawn(move || rx.recv().ok());
        // The test harness runs tests on worker threads, so we can only assert a lower bound.
        assert!(thread_count().unwrap() >= 2);
        assert!(
            matches!(ensure_single_threaded(), Err(ThreadCheckError::MultiThreaded(n)) if n >= 2)
        );
        tx.send(()).unwrap();
        handle.join().unwrap();
    }
}
