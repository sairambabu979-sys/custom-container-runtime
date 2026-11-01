//! `hull-runtime`: an OCI container runtime with a runc-compatible command line.
//!
//! This binary is deliberately thin: it parses arguments, sets up logging, and calls into the
//! `hull-runtime` library. It must also stay **single-threaded**, because `clone3` and user
//! namespaces require it (see `hull_sys::thread`). Nothing here may start a background thread,
//! which is why logging uses a plain synchronous writer.

#![forbid(unsafe_code)]

use std::io::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Mutex;
use std::time::Duration;

use clap::{Parser, Subcommand, ValueEnum};
use hull_runtime::run::{RunOptions, run};
use hull_runtime::{ContainerId, Error, StateStore, render_chain};

/// Exit code for failures of the runtime itself (as opposed to the container's own exit code).
/// 125 is the same convention Docker and Podman use.
const RUNTIME_FAILURE: u8 = 125;

#[derive(Debug, Parser)]
#[command(
    name = "hull-runtime",
    version,
    about = "An OCI container runtime built from first principles"
)]
struct Cli {
    /// Directory holding container state.
    #[arg(long, global = true, default_value = "/run/hull", env = "HULL_ROOT")]
    root: PathBuf,
    /// Write logs to this file instead of standard error.
    #[arg(long, global = true)]
    log: Option<PathBuf>,
    /// Log format (`json` is what containerd expects).
    #[arg(long, global = true, value_enum, default_value_t = LogFormat::Text)]
    log_format: LogFormat,
    /// Log debug messages.
    #[arg(long, global = true)]
    debug: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum LogFormat {
    Text,
    Json,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ListFormat {
    Table,
    Json,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Write a default config.json into a bundle directory.
    Spec {
        /// The bundle directory.
        #[arg(long, short, default_value = ".")]
        bundle: PathBuf,
    },
    /// Create a container and run its process in the foreground until it exits.
    Run {
        /// The bundle directory (containing config.json).
        #[arg(long, short, default_value = ".")]
        bundle: PathBuf,
        /// Write the container init's PID to this file.
        #[arg(long)]
        pid_file: Option<PathBuf>,
        /// Abort if container setup takes longer than this many seconds.
        #[arg(long, default_value_t = 60)]
        setup_timeout: u64,
        /// Detach from the container (not implemented until milestone M2).
        #[arg(long, short)]
        detach: bool,
        /// The container ID.
        id: String,
    },
    /// Print the state of a container as JSON.
    State {
        /// The container ID.
        id: String,
    },
    /// List containers.
    List {
        /// Output format.
        #[arg(long, short, value_enum, default_value_t = ListFormat::Table)]
        format: ListFormat,
        /// Print only container IDs.
        #[arg(long, short)]
        quiet: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    if let Err(e) = init_logging(&cli) {
        eprintln!("hull-runtime: cannot set up logging: {e}");
        return ExitCode::from(RUNTIME_FAILURE);
    }
    let store = StateStore::new(&cli.root);
    match execute(cli.command, &store) {
        Ok(code) => code,
        Err(e) => {
            let message = render_chain(&e);
            tracing::error!("{message}");
            eprintln!("hull-runtime: {message}");
            match e {
                Error::Init { exit_code: Some(code), .. } => {
                    ExitCode::from(u8::try_from(code).unwrap_or(RUNTIME_FAILURE))
                }
                _ => ExitCode::from(RUNTIME_FAILURE),
            }
        }
    }
}

fn execute(command: Command, store: &StateStore) -> hull_runtime::Result<ExitCode> {
    match command {
        Command::Spec { bundle } => {
            write_default_spec(&bundle)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Run { detach: true, .. } => Err(Error::Unsupported(
            "--detach is not implemented yet (planned for milestone M2)".into(),
        )),
        Command::Run { bundle, pid_file, setup_timeout, detach: false, id } => {
            let options = RunOptions {
                id: ContainerId::new(&id)?,
                bundle,
                pid_file,
                setup_timeout: Duration::from_secs(setup_timeout),
            };
            let code = run(store, &options)?;
            // Exit codes above 255 do not exist; the container's code is always in range.
            Ok(ExitCode::from(u8::try_from(code).unwrap_or(RUNTIME_FAILURE)))
        }
        Command::State { id } => {
            let state = store.load(&ContainerId::new(&id)?)?;
            print_json(&state)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::List { format, quiet } => {
            let states = store.list()?;
            if quiet {
                for state in &states {
                    println!("{}", state.id);
                }
            } else {
                match format {
                    ListFormat::Json => print_json(&states)?,
                    ListFormat::Table => print_table(&states),
                }
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn write_default_spec(bundle: &std::path::Path) -> hull_runtime::Result<()> {
    let path = bundle.join("config.json");
    let mut file =
        std::fs::OpenOptions::new().write(true).create_new(true).open(&path).map_err(|source| {
            Error::Io {
                context: format!("create {} (remove it first if it exists)", path.display()),
                source,
            }
        })?;
    file.write_all(hull_spec::DEFAULT_CONFIG_JSON.as_bytes())
        .map_err(|source| Error::Io { context: format!("write {}", path.display()), source })
}

fn print_json<T: serde::Serialize>(value: &T) -> hull_runtime::Result<()> {
    let json = serde_json::to_string_pretty(value).map_err(|e| Error::Io {
        context: "serialize output".into(),
        source: std::io::Error::other(e),
    })?;
    println!("{json}");
    Ok(())
}

fn print_table(states: &[hull_runtime::State]) {
    println!("{:<20} {:>8} {:<10} {:<40} CREATED", "ID", "PID", "STATUS", "BUNDLE");
    for s in states {
        let status_name = serde_json::to_value(s.status)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default();
        println!(
            "{:<20} {:>8} {:<10} {:<40} {}",
            s.id,
            s.pid,
            status_name,
            s.bundle.display(),
            s.created
        );
    }
}

fn init_logging(cli: &Cli) -> std::io::Result<()> {
    let level = if cli.debug { tracing::Level::DEBUG } else { tracing::Level::WARN };
    let builder = tracing_subscriber::fmt().with_max_level(level).with_target(false);
    match (&cli.log, cli.log_format) {
        (Some(path), format) => {
            let file = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
            let builder = builder.with_writer(Mutex::new(file)).with_ansi(false);
            match format {
                LogFormat::Json => builder.json().init(),
                LogFormat::Text => builder.init(),
            }
        }
        (None, LogFormat::Json) => builder.with_writer(std::io::stderr).json().init(),
        (None, LogFormat::Text) => builder.with_writer(std::io::stderr).init(),
    }
    Ok(())
}
