// Copyright 2026 Doni Crosby
// SPDX-License-Identifier: Apache-2.0
//! CLI state on disk: server URL + account (plaintext config) and the
//! passphrase-sealed keyring holding the session.
//!
//! Layout:
//! - `<dir>/config.json` — { server, account }, 0600
//! - `<dir>/keyring`     — sealed session, 0600 (cryptile_core::keyring)

use std::fs;
use std::path::PathBuf;

use cryptile_core::{Keyring, SecretString};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct StateConfig {
    pub server: String,
    pub account: String,
}

#[derive(Debug, Clone)]
pub struct State {
    dir: PathBuf,
}

impl State {
    pub fn open() -> Self {
        Self::dir_default()
    }

    pub fn dir_default() -> Self {
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
            .unwrap_or_else(|| PathBuf::from("."));
        Self {
            dir: base.join("cryptile"),
        }
    }

    /// Test/boundary override: explicit state dir.
    pub fn with_dir(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub fn dir(&self) -> &std::path::Path {
        &self.dir
    }

    fn config_path(&self) -> PathBuf {
        self.dir.join("config.json")
    }

    pub(crate) fn keyring_path(&self) -> PathBuf {
        self.dir.join("keyring")
    }

    /// Sealed sync-cache file (backend-owned format; opaque to the CLI).
    pub fn cache_path(&self) -> PathBuf {
        self.dir.join("cache").join("cipher-index")
    }

    /// Whether a login exists (config + keyring both present).
    pub fn logged_in(&self) -> bool {
        self.config_path().is_file() && self.keyring_path().is_file()
    }

    /// Write config + sealed session atomically-ish: keyring last, config
    /// first, so a crash leaves "not logged in" rather than a torn state.
    pub fn save_login(
        &self,
        cfg: &StateConfig,
        session_json: &str,
        passphrase: &SecretString,
    ) -> std::io::Result<()> {
        fs::create_dir_all(&self.dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&self.dir, fs::Permissions::from_mode(0o700));
            let raw = serde_json::to_string_pretty(cfg).expect("config serializes");
            let tmp = self.config_path().with_extension("json.tmp");
            fs::write(&tmp, raw)?;
            let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600));
            fs::rename(&tmp, self.config_path())?;
        }
        #[cfg(not(unix))]
        {
            let raw = serde_json::to_string_pretty(cfg).expect("config serializes");
            let tmp = self.config_path().with_extension("json.tmp");
            fs::write(&tmp, raw)?;
            fs::rename(&tmp, self.config_path())?;
        }
        Keyring::with_path(self.keyring_path())
            .save(session_json, passphrase)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        Ok(())
    }

    /// Load config (server + account). Err(io::ErrorKind::NotFound) if absent.
    pub fn load_config(&self) -> std::io::Result<StateConfig> {
        let raw = fs::read_to_string(self.config_path())?;
        Ok(serde_json::from_str(&raw)?)
    }

    /// Unseal the stored session with the keyring passphrase.
    pub fn load_session(
        &self,
        passphrase: &SecretString,
    ) -> Result<cryptile_core::Session, String> {
        let sealed = Keyring::with_path(self.keyring_path())
            .load(passphrase)
            .map_err(|e| e.to_string())?;
        Ok(cryptile_core::Session {
            provider: "vw".into(),
            handle: sealed.as_str().to_string(),
        })
    }
}
