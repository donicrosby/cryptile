//! cryptile CLI.
//!
//! MVP surface: parse refs, dispatch on scheme, print metadata. Backends land
//! as crates implementing the Provider trait and register in [`registry`].

mod registry;

use std::process::ExitCode;

use clap::{Parser, Subcommand};

use cryptile_core::Ref;

/// Redacted by default; raw values only at the stdout boundary under policy.
#[derive(Parser)]
#[command(name = "cryptile", version, about, verbatim_doc_comment)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Validate a reference and show how it parses
    Parse { r#ref: String },
    /// List registered backends
    Backends,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Parse { r#ref } => match Ref::parse(&r#ref) {
            Ok(parsed) => {
                println!(
                    "scheme={}\nlocus={}\nfield={}",
                    parsed.scheme, parsed.locus, parsed.field
                );
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(2)
            }
        },
        Command::Backends => {
            for b in registry::backends() {
                println!("{b}");
            }
            ExitCode::SUCCESS
        }
    }
}
