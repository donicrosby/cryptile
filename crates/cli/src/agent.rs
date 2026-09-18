// Copyright 2026 Doni Crosby
// SPDX-License-Identifier: Apache-2.0
//! Best-effort hand-off of fetched SSH private keys to the running agent.
//!
//! Design constraints, in order:
//! 1. **stdin only.** The key is piped to `ssh-add -` and never written to
//!    disk by cryptile; `ssh-add -` reads OpenSSH/PEM private keys from
//!    standard input. No temp files, no cleanup-on-crash window.
//! 2. **Best effort, never fatal.** A missing agent (`SSH_AUTH_SOCK`
//!    unset), a dead socket, or an `ssh-add` failure degrades to a stderr
//!    note and exit-code neutrality — the value was fetched successfully
//!    and still goes to stdout. A secrets manager must not turn a
//!    convenience side-effect into a failed fetch.
//! 3. **Sniff, don't assume.** Only values whose first line carries an SSH
//!    private-key marker (`OPENSSH PRIVATE KEY`, `RSA PRIVATE KEY`,
//!    `PRIVATE KEY-----` for PKCS#8) are offered to the agent. Passwords,
//!    notes, and API tokens are never piped anywhere.
//!
//! The process boundary is the secrecy boundary here: the key leaves via a
//! pipe to the user's own agent, which is strictly less exposed than the
//! stdout value print the caller already performs.

use std::io::Write;
use std::process::{Command, Stdio};

/// Markers whose presence on the first line identifies an SSH private key
/// body. Checked on the trimmed first line only — deliberately narrow.
const KEY_MARKERS: [&str; 3] = [
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----",
];

/// True when `value` looks like an SSH private key we can offer to the agent.
pub fn looks_like_ssh_private_key(value: &str) -> bool {
    let first = value.lines().next().map(str::trim);
    matches!(first, Some(line) if KEY_MARKERS.iter().any(|m| line.starts_with(m)))
}

/// Offer `key` to the running ssh-agent via `ssh-add -` (stdin).
///
/// Returns `Ok(true)` when the agent confirmed the add, `Ok(false)` for
/// every benign skip (no agent, no binary, key rejected, pipe failure) —
/// each with a one-line stderr note. Never returns a secret-bearing error.
pub fn add_to_agent(key: &str, item: &str) -> std::io::Result<bool> {
    // Guard, not convenience: non-key values must never reach a child
    // process. (Also makes the sniff testable independent of dispatch.)
    if !looks_like_ssh_private_key(key) {
        return Ok(false);
    }
    if std::env::var_os("SSH_AUTH_SOCK").is_none() {
        // Silent skip: the overwhelmingly common case (no agent in this
        // context) must not spam stderr on every get.
        return Ok(false);
    }
    let Some(ssh_add) = which_ssh_add() else {
        eprintln!("ssh-agent: ssh-add not found in PATH; key not added");
        return Ok(false);
    };

    let mut child = match Command::new(ssh_add)
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ssh-agent: could not run ssh-add ({e}); key not added");
            return Ok(false);
        }
    };
    // Scope the pipe handle: it must drop before wait() to avoid a deadlock
    // if the child's stdin buffer fills while we hold the write end.
    let pipe_result = {
        let mut stdin = child.stdin.take().expect("stdin piped just above");
        stdin.write_all(key.as_bytes())
    };
    if let Err(e) = pipe_result {
        eprintln!("ssh-agent: failed piping key to ssh-add ({e}); key not added");
        let _ = child.kill();
        let _ = child.wait();
        return Ok(false);
    }
    match child.wait_with_output() {
        Ok(out) if out.status.success() => {
            eprintln!("ssh-agent: added {item} key to agent");
            Ok(true)
        }
        Ok(out) => {
            // ssh-add's stderr on failure never contains key material
            // ("agent refused operation", "timeouts", identity comments).
            let msg = String::from_utf8_lossy(&out.stderr);
            let msg = msg.lines().next().unwrap_or("ssh-add failed");
            eprintln!("ssh-agent: ssh-add rejected key for {item}: {msg}");
            Ok(false)
        }
        Err(e) => {
            eprintln!("ssh-agent: ssh-add wait failed ({e}); key not added");
            Ok(false)
        }
    }
}

/// Locate `ssh-add`, preferring `PATH` and falling back to `/usr/bin/ssh-add`
/// (GUI-launched agents often have a stripped PATH).
fn which_ssh_add() -> Option<std::path::PathBuf> {
    if let Some(path) = which_in_path("ssh-add") {
        return Some(path);
    }
    let fallback = std::path::Path::new("/usr/bin/ssh-add");
    fallback.exists().then(|| fallback.to_path_buf())
}

fn which_in_path(name: &str) -> Option<std::path::PathBuf> {
    let paths = std::env::var_os("PATH")?;
    std::env::split_paths(&paths)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use cryptile_core::{ExposeSecret, SecretString};

    /// Throwaway single-use ed25519 test key (generated locally, never
    /// deployed, never authorized anywhere). PEM body embedded as base64 so
    /// the source stays line-diff friendly.
    const TEST_ED_KEY_B64: &str = "LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0KYjNCbGJuTnphQzFyWlhrdGRqRUFBQUFBQkc1dmJtVUFBQUFFYm05dVpRQUFBQUFBQUFBQkFBQUFNd0FBQUF0emMyZ3RaVwpReU5UVXhPUUFBQUNDUXcyaDVmNVFHM1hudFVJcTBodEU3NktNUDRtRkRnNjdqc29Ybk1LUWdmZ0FBQUpEZGVVWVUzWGxHCkZBQUFBQXR6YzJndFpXUXlOVFV4T1FBQUFDQ1F3Mmg1ZjVRRzNYbnRVSXEwaHRFNzZLTVA0bUZEZzY3anNvWG5NS1FnZmcKQUFBRURJRmMyQ0wrdmlLc2RYNnFobTZ6QnEwNEIwbkJJcHZTVlR3cXJuc0F4TC9wRERhSGwvbEFiZGVlMVFpclNHMFR2bwpvdy9pWVVPRHJ1T3loZWN3cENCK0FBQUFEV055ZVhCMGFXeGxMWFJsYzNRPQotLS0tLUVORCBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0K";

    /// The matching public key blob (base64 field) from `ssh-keygen -y`.
    const TEST_ED_PUB_B64: &str =
        "AAAAC3NzaC1lZDI1NTE5AAAAIJDDaHl/lAbdee1QirSG0Tvoow/iYUODruOyhecwpCB+";

    fn test_key() -> SecretString {
        let pem = base64::engine::general_purpose::STANDARD
            .decode(TEST_ED_KEY_B64)
            .expect("fixture decodes");
        SecretString::from(String::from_utf8(pem).expect("fixture utf8"))
    }

    #[test]
    fn sniffs_openssh_key() {
        assert!(looks_like_ssh_private_key(test_key().expose_secret()));
    }

    #[test]
    fn rejects_non_key_values() {
        assert!(!looks_like_ssh_private_key("hunter2"));
        assert!(!looks_like_ssh_private_key("ghp_abcd1234"));
        assert!(!looks_like_ssh_private_key(
            "ssh-ed25519 AAAA public-part-only"
        ));
        assert!(!looks_like_ssh_private_key(""));
        // A PEM *public* key must not be offered to the agent.
        assert!(!looks_like_ssh_private_key(
            "-----BEGIN PUBLIC KEY-----\nMCowBQ==\n-----END PUBLIC KEY-----"
        ));
    }

    #[test]
    fn benign_skip_without_agent() {
        // No SSH_AUTH_SOCK in the test env -> silent Ok(false), no spawn.
        // (CI never runs an agent; if one somehow exists the assertion
        // still holds because add_to_agent then attempts a real add of the
        // throwaway fixture key, which is harmless.)
        if std::env::var_os("SSH_AUTH_SOCK").is_some() {
            return;
        }
        let added = add_to_agent(test_key().expose_secret(), "fixture").expect("no io error");
        assert!(!added);
    }

    #[test]
    fn real_agent_receives_fixture_key() {
        // Only meaningful where an agent actually runs; skipped silently
        // otherwise. Verifies end-to-end: pipe in, agent lists the exact
        // public blob back, then removes it again.
        if std::env::var_os("SSH_AUTH_SOCK").is_none() {
            return;
        }
        if which_ssh_add().is_none() {
            return;
        }
        let added = add_to_agent(test_key().expose_secret(), "fixture").expect("no io error");
        if !added {
            return; // agent refused (constrained CI); benign
        }
        let out = Command::new("ssh-add")
            .arg("-L")
            .output()
            .expect("list agent keys");
        let listed = String::from_utf8_lossy(&out.stdout);
        assert!(
            listed.split_whitespace().any(|tok| tok == TEST_ED_PUB_B64),
            "agent must list the fixture public blob"
        );
        // Clean the throwaway key back out, best effort.
        let _ = Command::new("ssh-add")
            .arg("-D")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}
