# Copyright 2026 Doni Crosby
# SPDX-License-Identifier: Apache-2.0
"""Conformance run: the real Hermes SecretSourceConformance kit against
CryptileSource. Requires a hermes-agent checkout (HERMES_REPO, default
/tmp/hermes); skipped with a clear notice when unavailable."""

import os
import sys
from pathlib import Path

import pytest

HERMES_REPO = Path(os.environ.get("HERMES_REPO", "/tmp/hermes"))
if not (_HERMES := HERMES_REPO).is_dir():
    pytest.skip("hermes-agent checkout not present; skipping conformance", allow_module_level=True)

sys.path.insert(0, str(HERMES_REPO))

from integrations.hermes import CryptileSource  # noqa: E402
from tests.secret_sources.conformance import SecretSourceConformance  # noqa: E402


class TestCryptileConformance(SecretSourceConformance):
    @pytest.fixture
    def source(self):
        return CryptileSource()
