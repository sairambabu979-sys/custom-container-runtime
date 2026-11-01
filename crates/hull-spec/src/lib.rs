//! Loading and validating OCI runtime configurations (`config.json`).
//!
//! # Fail closed
//!
//! hull is built one milestone at a time, so at any moment there are spec features it does not
//! implement yet. The dangerous way to handle that is to parse the field and ignore it. A
//! `config.json` that asks for a seccomp filter would then run *without* one, and nothing would
//! say so.
//!
//! [`validate`] therefore rejects every field that hull understands but does not implement yet,
//! and names the milestone that will add it. That is different from *unknown* fields: the OCI
//! spec says runtimes MUST ignore properties they do not recognize, so [`load`] only reports
//! those as warnings.
//!
//! Validation runs before the runtime has any side effect (no directories, no processes), and it
//! collects *every* problem instead of stopping at the first, so one run of `hull-runtime` shows
//! the whole list.

#![forbid(unsafe_code)]

mod load;
mod milestone;
pub mod mounts;
mod validate;

pub use load::{LoadError, LoadedSpec, load};
pub use milestone::Milestone;
pub use oci_spec::runtime as oci;
pub use validate::{ValidationErrors, Violation, ViolationKind, validate};

/// The JSON written by `hull-runtime spec`.
pub const DEFAULT_CONFIG_JSON: &str = include_str!("default-config.json");

/// The default configuration as a parsed [`oci::Spec`].
pub fn default_spec() -> Result<oci::Spec, serde_json::Error> {
    serde_json::from_str(DEFAULT_CONFIG_JSON)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_parses_and_validates() {
        let spec = default_spec().unwrap();
        validate(&spec).unwrap();
    }
}
