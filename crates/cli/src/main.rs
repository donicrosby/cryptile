//! cryptile CLI.
//!
//! MVP surface: login (TTY-gated), get, list, parse, backends. Values reach
//! stdout only in `get` (single field), and never in logs. Sessions persist
//! passphrase-sealed in the keyring; tokens rotate silently on 401 (4.5).

mod ops;
mod registry;
mod state;

use std::io::IsTerminal;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use cryptile_core::provider::Provider;
use cryptile_core::{Keyring, Ref};
use cryptile_vaultwarden::VaultwardenProvider;
use secrecy::SecretString as SecStr;

use state::{State, StateConfig};

/// Redacted by default; raw values only at the stdout boundary under policy.
#[derive(Parser)]
#[command(name = "cryptile", version, about, verbatim_doc_comment)]
struct Cli {
    /// State dir override (default: $XDG_CONFIG_HOME/cryptile or ~/.config/cryptile)
    #[arg(long, global = true)]
    state_dir: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Log in to the Vaultwarden server and store a sealed session
    Login {
        /// Server base URL, e.g. https://vault.example.com
        #[arg(long)]
        server: String,
        /// Account email
        #[arg(long)]
        account: String,
    },
    /// Print one secret field value (vw://collection/item#field)
    Get { r#ref: String },
    /// List namespaces, or items in one namespace (metadata only)
    List {
        /// Namespace (collection) name; omit to list namespaces
        namespace: Option<String>,
    },
    /// Validate a reference and show how it parses
    Parse { r#ref: String },
    /// List registered backends
    Backends,
}

fn die(msg: String, code: u8) -> ExitCode {
    eprintln!("error: {msg}");
    ExitCode::from(code)
}

fn read_passphrase(prompt: &str) -> Result<SecStr, String> {
    if !std::io::stdin().is_terminal() {
        return Err("refusing to read keyring passphrase from non-TTY stdin".into());
    }
    let p1 = rpassword::prompt_password(prompt).map_err(|e| e.to_string())?;
    let p2 = rpassword::prompt_password("confirm passphrase: ").map_err(|e| e.to_string())?;
    if p1 != p2 {
        return Err("passphrases did not match".into());
    }
    Ok(SecStr::from(p1))
}

fn read_secret(prompt: &str) -> Result<SecStr, String> {
    if !std::io::stdin().is_terminal() {
        return Err("refusing to read secret from non-TTY stdin".into());
    }
    rpassword::prompt_password(prompt)
        .map(SecStr::from)
        .map_err(|e| e.to_string())
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let state = match &cli.state_dir {
        Some(d) => State::with_dir(d),
        None => State::open(),
    };

    match cli.command {
        Command::Parse { r#ref } => match Ref::parse(&r#ref) {
            Ok(p) => {
                println!("scheme={}\nlocus={}\nfield={}", p.scheme, p.locus, p.field);
                ExitCode::SUCCESS
            }
            Err(e) => die(format!("{e}"), 2),
        },
        Command::Backends => {
            for b in registry::backends() {
                println!("{b}");
            }
            ExitCode::SUCCESS
        }
        Command::Login { server, account } => {
            let passphrase = match read_passphrase("keyring passphrase: ") {
                Ok(p) => p,
                Err(e) => return die(e, 2),
            };
            let secret = match read_secret("master password: ") {
                Ok(p) => p,
                Err(e) => return die(e, 2),
            };
            let provider = match VaultwardenProvider::new(&server) {
                Ok(p) => p,
                Err(e) => return die(e.to_string(), 2),
            };
            let session = match provider
                .login(cryptile_core::LoginParams {
                    account: account.clone(),
                    secret,
                })
                .await
            {
                Ok(s) => s,
                Err(e) => return die(e.to_string(), 4),
            };
            let cfg = StateConfig { server, account };
            if let Err(e) = state.save_login(&cfg, &session.handle, &passphrase) {
                return die(format!("saving state: {e}"), 5);
            }
            println!("logged in; session sealed in {}", state.dir().display());
            ExitCode::SUCCESS
        }
        Command::Get { r#ref } => {
            let r = match Ref::parse(&r#ref) {
                Ok(r) => r,
                Err(e) => return die(format!("{e}"), 2),
            };
            let (cfg, passphrase, session) = match load_state(&state) {
                Ok(v) => v,
                Err(msg) => return die(msg, 3),
            };
            let provider = match VaultwardenProvider::new(&cfg.server) {
                Ok(p) => p,
                Err(e) => return die(e.to_string(), 2),
            };
            match ops::get(&provider, session, &r).await {
                Ok((sess, value)) => {
                    reseal(&state, &sess, &passphrase);
                    println!("{value}");
                    ExitCode::SUCCESS
                }
                Err(e) => die(e, 4),
            }
        }
        Command::List { namespace } => {
            let (cfg, passphrase, session) = match load_state(&state) {
                Ok(v) => v,
                Err(msg) => return die(msg, 3),
            };
            let provider = match VaultwardenProvider::new(&cfg.server) {
                Ok(p) => p,
                Err(e) => return die(e.to_string(), 2),
            };
            match ops::list(&provider, session, namespace).await {
                Ok((sess, names)) => {
                    reseal(&state, &sess, &passphrase);
                    for n in names {
                        println!("{n}");
                    }
                    ExitCode::SUCCESS
                }
                Err(e) => die(e, 4),
            }
        }
    }
}

/// Load config + unseal session. Errors carry an exit-code-worthy message.
fn load_state(state: &State) -> Result<(StateConfig, SecStr, cryptile_core::Session), String> {
    if !state.logged_in() {
        return Err("not logged in; run `cryptile login`".into());
    }
    let cfg = state.load_config().map_err(|e| format!("config: {e}"))?;
    if !std::io::stdin().is_terminal() {
        return Err("refusing to read keyring passphrase from non-TTY stdin".into());
    }
    let passphrase = rpassword::prompt_password("keyring passphrase: ")
        .map(SecStr::from)
        .map_err(|e| e.to_string())?;
    let session = state.load_session(&passphrase)?;
    Ok((cfg, passphrase, session))
}

fn reseal(state: &State, session: &cryptile_core::Session, passphrase: &SecStr) {
    if let Err(e) = Keyring::with_path(state.keyring_path()).save(&session.handle, passphrase) {
        eprintln!("warn: could not re-seal refreshed session: {e}");
    }
}
