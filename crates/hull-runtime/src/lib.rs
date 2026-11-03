//! The core of `hull-runtime`: an OCI runtime built directly on Linux namespaces.
//!
//! Start reading at [`run::run`], which follows a container from `config.json` to exit code. The
//! parent/child split is explained in [`sync`], and the code that runs inside the new namespaces
//! starts at `init::child_main`.
//!
//! | Module | Responsibility |
//! |---|---|
//! | [`run`] | Parent side of `run` and `create`: validate, register, `clone3`, supervise |
//! | [`lifecycle`] | `start`, `kill`, `delete` on an existing container |
//! | `init` | Child side: everything between `clone3` and `execve` |
//! | [`sync`] | The message protocol between the two |
//! | `rootfs`, `mounts`, `devices` | Building the container's `/` and switching to it |
//! | `process` | rlimits, user identity, working directory, `PATH` lookup |
//! | [`state`] | `/run/hull/<id>/state.json` and locking |

#![forbid(unsafe_code)]

mod devices;
mod error;
mod id;
mod idmap;
mod init;
pub mod lifecycle;
mod mounts;
mod process;
mod procfs;
mod rootfs;
pub mod run;
pub mod state;
pub mod sync;
mod time;

pub(crate) use error::Context;
pub use error::{Error, Result, render_chain};
pub use id::ContainerId;
pub use process::find_executable;
pub use state::{State, StateStore, Status};
