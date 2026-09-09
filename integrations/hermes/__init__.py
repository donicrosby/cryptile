"""Cryptile secret source for Hermes.

Bridges Hermes' secret-source contract to the `cryptile` CLI: each
`env: {VAR: vw://collection/item#field}` binding is resolved by invoking
`cryptile get --passphrase-env <VAR>` once per ref, with an allowlisted
child environment and stdin closed. The plugin implements no Vaultwarden
protocol, crypto, or keyring logic — cryptile owns all of that, and its
typed exit codes are translated 1:1 onto Hermes' ErrorKind taxonomy.

Import contract: when installed under ~/.hermes/plugins/cryptile/, the
Hermes runtime provides `agent.secret_sources.base`. The try/except
fallback keeps the module importable in dev/test environments where the
package root differs (conformance tests add the Hermes repo to sys.path).
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    from agent.secret_sources.base import (
        ErrorKind,
        FetchResult,
        SecretSource,
        is_valid_env_name,
        run_secret_cli,
    )
except ImportError as _exc:  # pragma: no cover — dev/test convenience
    raise ImportError(
        "CryptileSource needs the Hermes runtime (agent.secret_sources.base). "
        "Install under ~/.hermes/plugins/cryptile/ or add the hermes-agent "
        "repo root to sys.path for tests."
    ) from _exc

DEFAULT_PASSPHRASE_ENV = "CRYPTILE_PASSPHRASE"
_REF_SCHEME = "vw://"

# cryptile exit codes (stable contract, see crates/cli/src/main.rs):
#   2 ref parse/usage, 3 auth/no-session/wrong passphrase, 4 transport/backend,
#   5 not-found. Anything else is a bug.
_EXIT_KINDS = {
    2: ErrorKind.REF_INVALID,
    3: ErrorKind.AUTH_FAILED,
    4: ErrorKind.NETWORK,
    5: ErrorKind.EMPTY_VALUE,
}

_RELOGIN_HINT = (
    "Run `cryptile login --server <url> --account <email>` to re-establish "
    "the sealed session (passphrase: {token_env})."
)
_MISSING_BINARY_HINT = "Install cryptile (cargo install --git https://github.com/donicrosby/cryptile) and ensure `cryptile` is on PATH, or set secrets.cryptile.binary_path."


class CryptileSource(SecretSource):
    """Mapped source: explicit VAR -> vw:// binding per secret."""

    name = "cryptile"
    label = "Cryptile"
    shape = "mapped"
    scheme = "vw"
    token_env_key = "passphrase_env"
    default_token_env = DEFAULT_PASSPHRASE_ENV
    # An explicit VAR->vw:// binding is the strongest user intent; a stale
    # .env line must not silently defeat it (same stance as 1Password).
    override_existing_default = True
    remediation_hints = {
        ErrorKind.AUTH_FAILED: _RELOGIN_HINT,
        ErrorKind.AUTH_EXPIRED: _RELOGIN_HINT,
        ErrorKind.BINARY_MISSING: _MISSING_BINARY_HINT,
    }

    def config_schema(self) -> dict:
        return {
            "enabled": {"description": "Master switch", "default": False},
            "env": {"description": "Map of ENV_VAR -> vw://collection/item#field reference", "default": {}},
            "binary_path": {"description": "Pin the cryptile binary (empty = resolve via PATH)", "default": ""},
            "state_dir": {"description": "cryptile --state-dir override (empty = default ~/.config/cryptile)", "default": ""},
            "passphrase_env": {"description": "Env var holding the keyring passphrase", "default": DEFAULT_PASSPHRASE_ENV},
            "timeout_seconds": {"description": "Wall-clock budget for the whole fetch", "default": 120},
            "override_existing": {"description": "Resolved values overwrite .env/shell values", "default": True},
        }

    # ---- helpers ----------------------------------------------------------

    @staticmethod
    def _validate_env_map(env_map) -> Tuple[Dict[str, str], List[str]]:
        """Return ({VAR: ref}, warnings) keeping only well-formed bindings."""
        valid: Dict[str, str] = {}
        warnings: List[str] = []
        if not isinstance(env_map, dict) or not env_map:
            return valid, warnings
        for var, ref in env_map.items():
            var_s, ref_s = str(var), str(ref)
            if not is_valid_env_name(var_s):
                warnings.append(f"secrets.cryptile.env: skipping invalid env var name {var_s!r}")
            elif not ref_s.startswith(_REF_SCHEME):
                warnings.append(
                    f"secrets.cryptile.env: skipping non-vw reference for {var_s} (got {ref_s!r})"
                )
            else:
                valid[var_s] = ref_s
        return valid, warnings

    @staticmethod
    def _find_binary(pin: str) -> Optional[str]:
        if pin:
            p = Path(pin).expanduser()
            # Mode-bits check, not os.access: tmpfs idmapping makes access(X)
            # unreliable for files created by other uids (container sandboxes).
            try:
                if p.is_file() and (p.stat().st_mode & 0o111):
                    return str(p)
            except OSError:
                return None
            return None
        return shutil.which("cryptile")

    # ---- contract ---------------------------------------------------------

    def fetch(self, cfg: dict, home_path: Path) -> FetchResult:
        cfg = cfg if isinstance(cfg, dict) else {}
        result = FetchResult()

        env_map, warnings = self._validate_env_map(cfg.get("env"))
        result.warnings.extend(warnings)
        if not env_map:
            return result.fail(
                "secrets.cryptile.enabled is true but the env: map is empty. "
                "Add ENV_VAR: vw://collection/item#field entries.",
                ErrorKind.NOT_CONFIGURED,
            )

        binary = self._find_binary(str(cfg.get("binary_path") or ""))
        result.binary_path = Path(binary) if binary else None
        if binary is None:
            return result.fail(
                "cryptile binary not found on PATH"
                + (f" (binary_path={cfg.get('binary_path')!r})" if cfg.get("binary_path") else "")
                + ".",
                ErrorKind.BINARY_MISSING,
            )

        token_env = self.token_env(cfg)
        allow_env = [token_env] if token_env else []
        state_dir = str(cfg.get("state_dir") or "")

        for var, ref in env_map.items():
            argv = [binary, "get"]
            if state_dir:
                argv += ["--state-dir", state_dir]
            argv += ["--passphrase-env", token_env, "--", ref]

            try:
                proc = run_secret_cli(argv, allow_env=allow_env, timeout=30)
            except RuntimeError as exc:
                return result.fail(f"cryptile get failed: {exc}", ErrorKind.NETWORK)

            if proc.returncode != 0:
                kind = _EXIT_KINDS.get(proc.returncode, ErrorKind.INTERNAL)
                return result.fail(
                    f"cryptile get exited {proc.returncode} for {var}: "
                    f"{(proc.stderr or '').strip()[:200]}",
                    kind,
                )
            value = (proc.stdout or "").strip()
            if not value:
                return result.fail(
                    f"cryptile get returned empty output for {var}.", ErrorKind.EMPTY_VALUE
                )
            result.secrets[var] = value

        return result


def register(ctx):
    ctx.register_secret_source(CryptileSource())
