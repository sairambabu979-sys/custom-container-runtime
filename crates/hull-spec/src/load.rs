use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::oci::Spec;

/// A parsed `config.json` plus the properties that were present but not understood.
#[derive(Debug)]
pub struct LoadedSpec {
    /// The parsed configuration.
    pub spec: Spec,
    /// JSON paths (like `linux.fooBar`) that the parser did not recognize and therefore dropped.
    pub unknown_fields: Vec<String>,
}

/// Error returned by [`load`].
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    /// The file could not be read.
    #[error("cannot read {path}: {source}")]
    Read {
        /// The config path.
        path: PathBuf,
        /// The underlying error.
        source: std::io::Error,
    },
    /// The file is not valid JSON or does not match the spec's schema.
    #[error("cannot parse {path}: {source}")]
    Parse {
        /// The config path.
        path: PathBuf,
        /// The underlying error.
        source: serde_json::Error,
    },
}

/// Load and parse `config.json` from `path`.
pub fn load(path: &Path) -> Result<LoadedSpec, LoadError> {
    let text = std::fs::read_to_string(path)
        .map_err(|source| LoadError::Read { path: path.to_owned(), source })?;
    parse(&text).map_err(|source| LoadError::Parse { path: path.to_owned(), source })
}

fn parse(text: &str) -> Result<LoadedSpec, serde_json::Error> {
    let raw: Value = serde_json::from_str(text)?;
    let spec: Spec = serde_json::from_value(raw.clone())?;
    // Serde silently drops properties it does not know. To find them, serialize the parsed spec
    // back to JSON and look for keys that were in the input but did not survive the round trip.
    let round_trip = serde_json::to_value(&spec)?;
    let mut unknown_fields = Vec::new();
    find_dropped_keys(&raw, &round_trip, "", &mut unknown_fields);
    unknown_fields.sort();
    Ok(LoadedSpec { spec, unknown_fields })
}

fn find_dropped_keys(raw: &Value, kept: &Value, path: &str, out: &mut Vec<String>) {
    match (raw, kept) {
        (Value::Object(raw), Value::Object(kept)) => {
            for (key, raw_value) in raw {
                let child = if path.is_empty() { key.clone() } else { format!("{path}.{key}") };
                match kept.get(key) {
                    Some(kept_value) => find_dropped_keys(raw_value, kept_value, &child, out),
                    // `"field": null` means "unset", which round-trips as absent. Not unknown.
                    None if raw_value.is_null() => {}
                    None => out.push(child),
                }
            }
        }
        (Value::Array(raw), Value::Array(kept)) => {
            for (i, (raw_item, kept_item)) in raw.iter().zip(kept).enumerate() {
                find_dropped_keys(raw_item, kept_item, &format!("{path}[{i}]"), out);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_unknown_fields_without_failing() {
        let text = r#"{
            "ociVersion": "1.1.0",
            "root": {"path": "rootfs", "shinyNewField": true},
            "process": {"cwd": "/", "args": ["sh"], "user": {"uid": 0, "gid": 0}},
            "hooks": null,
            "mounts": [{"destination": "/proc", "type": "proc", "x-vendor": 1}],
            "vendorExtension": {}
        }"#;
        let loaded = parse(text).unwrap();
        assert_eq!(
            loaded.unknown_fields,
            ["mounts[0].x-vendor", "root.shinyNewField", "vendorExtension"]
        );
    }

    #[test]
    fn default_config_has_no_unknown_fields() {
        let loaded = parse(crate::DEFAULT_CONFIG_JSON).unwrap();
        assert_eq!(loaded.unknown_fields, Vec::<String>::new());
    }
}
