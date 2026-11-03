//! The parent ⇄ child synchronization protocol.
//!
//! After `clone3`, the runtime (parent) and the container's init (child) are separate processes
//! that must take turns. The child cannot finish setting up a user namespace until the parent has
//! written its ID maps, and the parent must learn whether setup worked, which can fail deep inside
//! the child, behind a `pivot_root`.
//!
//! The channel is a `SOCK_SEQPACKET` Unix socket pair:
//!
//! - *Sequenced packets* preserve message boundaries, so one `send` is one `recv`, with no framing
//!   code and no partial reads.
//! - Both ends are close-on-exec. When the child's `execve` succeeds, the kernel closes the child's
//!   end and the parent reads EOF. So EOF after [`ChildMessage::Ready`] *means* "exec succeeded",
//!   without any message having to be sent after the point of no return.
//!
//! ```text
//!   parent                                   child
//!     │                                        │  (blocked in recv)
//!     │── write uid_map / gid_map              │
//!     │── Continue ──────────────────────────► │
//!     │                                        │  hostname, mounts, pivot_root, user, cwd ...
//!     │ ◄────────────────────────────── Ready ─│
//!     │                                        │  execve()
//!     │ ◄──────────────────────── EOF (exec ok)│
//!     │ ◄─ Failed(InitError) (at any point) ───│
//! ```

use std::fmt;
use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::time::Duration;

use rustix::event::{PollFd, PollFlags, Timespec};
use rustix::net::{AddressFamily, RecvFlags, SendFlags, SocketFlags, SocketType};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// Bumped whenever a message changes shape. Both ends come from the same binary today, but a
/// mismatch must be a loud error rather than a misread message.
const PROTOCOL_VERSION: u32 = 1;

/// Upper bound on one message. Error messages are the largest payload.
const MAX_MESSAGE: usize = 64 * 1024;

/// What the child was doing when something went wrong.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stage {
    /// Waiting for the parent, adopting the namespace's root identity.
    Namespaces,
    /// Building the root filesystem and switching to it.
    Rootfs,
    /// Applying rlimits, user identity, working directory.
    Process,
    /// Created, waiting for `hull-runtime start`.
    Start,
    /// Executing the user's program.
    Exec,
}

impl fmt::Display for Stage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Namespaces => "namespace setup",
            Self::Rootfs => "root filesystem setup",
            Self::Process => "process setup",
            Self::Start => "wait for start",
            Self::Exec => "exec",
        })
    }
}

/// An error raised inside the container's init process.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InitError {
    /// Where it happened.
    pub stage: Stage,
    /// The full rendered error chain.
    pub message: String,
    /// The exit code the runtime should use, if the error maps to one.
    pub exit_code: Option<i32>,
}

/// Messages from parent to child.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ParentMessage {
    /// ID maps are written (if any); continue setting up.
    Continue,
}

/// Messages from child to parent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChildMessage {
    /// Setup is complete; the next step is `execve`.
    Ready,
    /// Setup failed. The child exits right after sending this.
    Failed(InitError),
}

#[derive(Serialize, Deserialize)]
struct Envelope<T> {
    version: u32,
    message: T,
}

/// Errors on the sync channel.
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    /// The socket failed.
    #[error("sync socket: {0}")]
    Io(#[from] io::Error),
    /// No message arrived in time.
    #[error("timed out after {0:?} waiting for the other side")]
    Timeout(Duration),
    /// A message could not be understood.
    #[error("sync protocol violation: {0}")]
    Protocol(String),
}

/// One end of the sync channel.
#[derive(Debug)]
pub struct SyncSocket(OwnedFd);

/// Create a connected pair: `(parent_end, child_end)`.
pub fn pair() -> io::Result<(SyncSocket, SyncSocket)> {
    let (a, b) = rustix::net::socketpair(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )?;
    Ok((SyncSocket(a), SyncSocket(b)))
}

impl SyncSocket {
    /// Send one message.
    pub fn send<T: Serialize>(&self, message: &T) -> Result<(), SyncError> {
        let bytes = serde_json::to_vec(&Envelope { version: PROTOCOL_VERSION, message })
            .map_err(|e| SyncError::Protocol(e.to_string()))?;
        if bytes.len() > MAX_MESSAGE {
            return Err(SyncError::Protocol(format!(
                "message of {} bytes is too large",
                bytes.len()
            )));
        }
        // MSG_NOSIGNAL: if the peer is gone, return EPIPE instead of killing us with SIGPIPE.
        let sent =
            rustix::net::send(&self.0, &bytes, SendFlags::NOSIGNAL).map_err(io::Error::from)?;
        if sent != bytes.len() {
            return Err(SyncError::Protocol("short send on a SEQPACKET socket".into()));
        }
        Ok(())
    }

    /// Receive one message. `Ok(None)` means the peer closed its end (EOF).
    pub fn recv<T: DeserializeOwned>(
        &self,
        timeout: Option<Duration>,
    ) -> Result<Option<T>, SyncError> {
        if let Some(limit) = timeout {
            let ts = Timespec {
                tv_sec: i64::try_from(limit.as_secs()).unwrap_or(i64::MAX),
                tv_nsec: limit.subsec_nanos().into(),
            };
            let mut fds = [PollFd::new(&self.0, PollFlags::IN)];
            loop {
                match rustix::event::poll(&mut fds, Some(&ts)) {
                    Ok(0) => return Err(SyncError::Timeout(limit)),
                    Ok(_) => break,
                    Err(rustix::io::Errno::INTR) => {}
                    Err(e) => return Err(SyncError::Io(e.into())),
                }
            }
        }
        let mut buf = vec![0u8; MAX_MESSAGE];
        let (_, len) = loop {
            match rustix::net::recv(self.0.as_fd(), &mut buf[..], RecvFlags::TRUNC) {
                Err(rustix::io::Errno::INTR) => {}
                other => break other.map_err(io::Error::from)?,
            }
        };
        if len == 0 {
            return Ok(None);
        }
        if len > MAX_MESSAGE {
            return Err(SyncError::Protocol(format!("message of {len} bytes was truncated")));
        }
        let envelope: Envelope<T> = serde_json::from_slice(&buf[..len])
            .map_err(|e| SyncError::Protocol(format!("undecodable message: {e}")))?;
        if envelope.version != PROTOCOL_VERSION {
            return Err(SyncError::Protocol(format!(
                "peer speaks protocol v{}, we speak v{PROTOCOL_VERSION}",
                envelope.version
            )));
        }
        Ok(Some(envelope.message))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_eof() {
        let (parent, child) = pair().unwrap();
        let error = InitError {
            stage: Stage::Rootfs,
            message: "mount /proc: EPERM".into(),
            exit_code: None,
        };
        child.send(&ChildMessage::Failed(error.clone())).unwrap();
        child.send(&ChildMessage::Ready).unwrap();
        drop(child);

        let timeout = Some(Duration::from_secs(5));
        assert_eq!(parent.recv(timeout).unwrap(), Some(ChildMessage::Failed(error)));
        assert_eq!(parent.recv(timeout).unwrap(), Some(ChildMessage::Ready));
        assert_eq!(parent.recv::<ChildMessage>(timeout).unwrap(), None);
    }

    #[test]
    fn times_out() {
        let (parent, _child) = pair().unwrap();
        let result = parent.recv::<ChildMessage>(Some(Duration::from_millis(20)));
        assert!(matches!(result, Err(SyncError::Timeout(_))));
    }

    #[test]
    fn rejects_other_protocol_versions() {
        let (parent, child) = pair().unwrap();
        rustix::net::send(&child.0, br#"{"version":99,"message":"Ready"}"#, SendFlags::empty())
            .unwrap();
        let result = parent.recv::<ChildMessage>(None);
        assert!(matches!(result, Err(SyncError::Protocol(m)) if m.contains("v99")));
    }
}
