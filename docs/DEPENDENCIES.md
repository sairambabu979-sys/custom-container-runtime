# Dependencies

Every third-party crate, and why it is worth its weight. Adding a dependency means adding a row.

| Crate | Used by | Why |
|---|---|---|
| `rustix` | sys, fs, runtime | Safe, typed wrappers for most Linux syscalls (mount API, `openat2`, pidfds, credentials). Avoids writing hundreds of `unsafe` blocks ourselves. |
| `libc` | sys | Constants and the raw `syscall()` entry point for the few calls rustix lacks (`clone3`, `mount_setattr`, `close_range`, signals). |
| `bitflags` | sys | Typed flag sets for namespaces and mount attributes. Already a rustix dependency. |
| `oci-spec` | spec, runtime | Serde types for the OCI runtime spec (ADR-007). Validation is ours. |
| `serde`, `serde_json` | everywhere | `config.json`, `state.json`, the sync protocol, probe output. |
| `thiserror` | spec, runtime | Derives `Error` for the error enums without hand-written boilerplate. |
| `clap` | runtime CLI | Argument parsing with generated help and a runc-compatible flag layout. |
| `tracing`, `tracing-subscriber` | runtime | Structured logs, including the JSON format containerd expects. Only the synchronous writer is used, because the runtime must stay single-threaded. |
| `tempfile` | tests | Temporary bundles and state roots that clean themselves up. |

Banned (enforced by `deny.toml`): `openssl` (use rustls when TLS arrives in M6) and `tokio` (no
async runtime anywhere, ADR-005).
