//! `shadenet-node`: resolve the configuration, then hand the process to `ShadeNode`.

use std::io::IsTerminal;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use shadenet_node::{Config, ShadeNode};

const LONG_VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (commit ",
    env!("SHADENET_COMMIT"),
    ")"
);

#[derive(Parser)]
#[command(name = "shadenet-node", version = LONG_VERSION, about = "Run a ShadeNet node")]
struct Cli {
    /// Log level [env: SHADENET_LOG_LEVEL]
    #[arg(long, global = true, value_enum)]
    log_level: Option<LogLevel>,
    /// Log format [env: SHADENET_LOG_FORMAT]
    #[arg(long, global = true, value_enum)]
    log_format: Option<LogFormat>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Serve tunnels (the default)
    Run,
}

#[derive(Clone, Copy, ValueEnum)]
enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Clone, Copy, ValueEnum)]
enum LogFormat {
    Auto,
    Json,
    Text,
    Pretty,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_logging(cli.log_level, cli.log_format);
    let (Some(Command::Run) | None) = cli.command;
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(e) => {
            eprintln!("shadenet-node: {}", chain(&e));
            return ExitCode::from(e.exit_code());
        }
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("shadenet-node: failed to start the async runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(ShadeNode::new(config).run()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("{}", chain(&e));
            ExitCode::from(e.exit_code())
        }
    }
}

fn chain(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}

fn init_logging(level: Option<LogLevel>, format: Option<LogFormat>) {
    use tracing_subscriber::EnvFilter;
    let level = level
        .or_else(|| {
            shadenet::env::var_lenient("LOG_LEVEL").and_then(|v| LogLevel::from_str(&v, true).ok())
        })
        .unwrap_or(LogLevel::Info);
    let format = format
        .or_else(|| {
            shadenet::env::var_lenient("LOG_FORMAT")
                .and_then(|v| LogFormat::from_str(&v, true).ok())
        })
        .unwrap_or(LogFormat::Auto);
    let ours = match level {
        LogLevel::Debug => "debug",
        LogLevel::Info => "info",
        LogLevel::Warn => "warn",
        LogLevel::Error => "error",
    };
    let filter = shadenet::env::var_lenient("LOG")
        .and_then(|spec| EnvFilter::try_new(spec).ok())
        .unwrap_or_else(|| EnvFilter::new(format!("warn,shadenet_node={ours}")));
    let terminal = std::io::stderr().is_terminal();
    let interactive = terminal
        && std::env::var("TERM").is_ok_and(|t| t != "dumb")
        && std::env::var("CI").is_err();
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr);
    let _ = match format {
        LogFormat::Json => builder.json().with_current_span(false).try_init(),
        LogFormat::Auto if !interactive => builder.json().with_current_span(false).try_init(),
        LogFormat::Auto | LogFormat::Pretty => {
            builder.with_ansi(terminal).with_target(false).try_init()
        }
        LogFormat::Text => builder.with_ansi(false).with_target(false).try_init(),
    };
}
