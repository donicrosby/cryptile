"""Pytest bootstrap: put the hermes-agent checkout on sys.path BEFORE the
cryptile plugin package (integrations/hermes/) is imported, so
`agent.secret_sources.base` resolves. Tests needing the Hermes runtime are
skipped when no checkout is present."""

import os
import sys
from pathlib import Path

_HERMES = Path(os.environ.get("HERMES_REPO", "/tmp/hermes"))
if _HERMES.is_dir() and str(_HERMES) not in sys.path:
    sys.path.insert(0, str(_HERMES))

collect_ignore = []
if not (_HERMES / "agent" / "secret_sources" / "base.py").is_file():
    # No Hermes checkout: skip plugin tests entirely rather than error.
    collect_ignore = ["integrations/hermes/test_source.py"]
