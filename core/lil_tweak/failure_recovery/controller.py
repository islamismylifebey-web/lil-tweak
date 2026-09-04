"""Authoritative coordinator for classification and recovery decisions."""

from __future__ import annotations

from typing import Any

from .classifier import FailureClassifier
from .contracts import (
    FailureCode,
    FailureRecoveryController as _TypingSentinel,
)
