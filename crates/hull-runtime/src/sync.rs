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
//!     │── Continue { state } ────────────────► │
//!     │                                        │  hostname, mounts, devices
//!     │ ◄──────────────────────── RootfsReady ─│
//!     │── prestart + createRuntime hooks       │
//!     │── RuntimeHooksDone ──────────────────► │
//!     │                                        │  createContainer hooks, pivot_root, user, cwd
//!     │ ◄──────────────────── Console (pty fd) │  (only with process.terminal)
//!     │ ◄────────────────────────────── Ready ─│
//!     │                                        │  execve()
//!     │ ◄──────────────────────── EOF (exec ok)│
//!     │ ◄─ Failed(InitError) (at any point) ───│
//! ```

use std::fmt;
use std::io;
use std::io::{IoSlice, IoSliceMut};
use std::mem::MaybeUninit;
use std::os::fd::{BorrowedFd, OwnedFd};
use std::time::Duration;

use rustix::event::{PollFd, PollFlags, Timespec};
use rustix::net::{
    AddressFamily, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags, SocketFlags, SocketType,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// Bumped whenever a message changes shape. Both ends come from the same binary today, but a
/// mismatch must be a loud error rather than a misread message.
const PROTOCOL_VERSION: u32 = 2;

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
    /// Running the hooks init runs itself (`createContainer`, `startContainer`).
    Hooks,
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
            Self::Hooks => "hooks",
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
    /// ID maps are written (if any); continue setting up. Carries the container's state (with
    /// its PID as the host sees it), which init passes to the hooks it runs itself.
    Continue {
        /// The container state at this point.
        state: Box<crate::State>,
    },
    /// The `prestart` and `createRuntime` hooks have run successfully.
    RuntimeHooksDone,
}

/// Messages from child to parent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChildMessage {
    /// Mounts and devices exist; the parent may run `prestart` and `createRuntime` hooks.
    RootfsReady,
    /// The pseudo-terminal master is attached to this message as `SCM_RIGHTS` ancillary data.
    Console,
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
        self.send_impl(message, None)
    }

    /// Send one message with a file descriptor attached (`SCM_RIGHTS`). The kernel installs a
    /// duplicate of `fd` in the receiving process: this is how a descriptor crosses a process
    /// boundary, here how the pseudo-terminal master leaves the container.
    pub fn send_with_fd<T: Serialize>(
        &self,
        message: &T,
        fd: BorrowedFd<'_>,
    ) -> Result<(), SyncError> {
        self.send_impl(message, Some(fd))
    }

    fn send_impl<T: Serialize>(
        &self,
        message: &T,
        fd: Option<BorrowedFd<'_>>,
    ) -> Result<(), SyncError> {
        let bytes = serde_json::to_vec(&Envelope { version: PROTOCOL_VERSION, message })
            .map_err(|e| SyncError::Protocol(e.to_string()))?;
        if bytes.len() > MAX_MESSAGE {
            return Err(SyncError::Protocol(format!(
                "message of {} bytes is too large",
                bytes.len()
            )));
        }
        let fds: Vec<BorrowedFd<'_>> = fd.into_iter().collect();
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut control = SendAncillaryBuffer::new(&mut space);
        if !fds.is_empty() && !control.push(SendAncillaryMessage::ScmRights(&fds)) {
            return Err(SyncError::Protocol("no room for SCM_RIGHTS".into()));
        }
        // MSG_NOSIGNAL: if the peer is gone, return EPIPE instead of killing us with SIGPIPE.
        let sent = rustix::net::sendmsg(
            &self.0,
            &[IoSlice::new(&bytes)],
            &mut control,
            SendFlags::NOSIGNAL,
        )
        .map_err(io::Error::from)?;
        if sent != bytes.len() {
            return Err(SyncError::Protocol("short send on a SEQPACKET socket".into()));
        }
        Ok(())
    }

    /// Receive one message. `Ok(None)` means the peer closed its end (EOF). A descriptor that
    /// arrives with the message is closed; use [`SyncSocket::recv_with_fd`] to keep it.
    pub fn recv<T: DeserializeOwned>(
        &self,
        timeout: Option<Duration>,
    ) -> Result<Option<T>, SyncError> {
        Ok(self.recv_with_fd(timeout)?.map(|(message, _fd)| message))
    }

    /// Receive one message and the descriptor attached to it, if any.
    pub fn recv_with_fd<T: DeserializeOwned>(
        &self,
        timeout: Option<Duration>,
    ) -> Result<Option<(T, Option<OwnedFd>)>, SyncError> {
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
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut control = RecvAncillaryBuffer::new(&mut space);
        let received = loop {
            // MSG_CMSG_CLOEXEC: a received descriptor must not leak into a later execve.
            let flags = RecvFlags::TRUNC | RecvFlags::CMSG_CLOEXEC;
            match rustix::net::recvmsg(
                &self.0,
                &mut [IoSliceMut::new(&mut buf)],
                &mut control,
                flags,
            ) {
                Err(rustix::io::Errno::INTR) => {}
                other => break other.map_err(io::Error::from)?,
            }
        };
        let mut fd = None;
        for message in control.drain() {
            if let RecvAncillaryMessage::ScmRights(fds) = message {
                for received_fd in fds {
                    fd.get_or_insert(received_fd);
                }
            }
        }
        let len = received.bytes;
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
        Ok(Some((envelope.message, fd)))
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
    fn passes_a_file_descriptor() {
        use std::io::{Read, Write};
        let (parent, child) = pair().unwrap();
        let (reader, writer) = std::io::pipe().unwrap();
        child.send_with_fd(&ChildMessage::Console, std::os::fd::AsFd::as_fd(&writer)).unwrap();
        drop(writer);
        let (message, fd) =
            parent.recv_with_fd::<ChildMessage>(Some(Duration::from_secs(5))).unwrap().unwrap();
        assert_eq!(message, ChildMessage::Console);
        // The received descriptor is a working copy of the pipe's write end.
        let mut writer = std::fs::File::from(fd.unwrap());
        writer.write_all(b"through the socket").unwrap();
        drop(writer);
        let mut text = String::new();
        let mut reader = reader;
        reader.read_to_string(&mut text).unwrap();
        assert_eq!(text, "through the socket");
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
