"""Result type shared across the runtime.

Subsystems report outcomes through ``RuntimeResult`` so that failures are
values, not exceptions crossing module boundaries.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Generic, TypeVar

T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class RuntimeResult(Generic[T]):
    """Typed outcome wrapper used between foundation components.

    ``ok`` is True only when ``value`` holds a usable payload. Errors carry
    a machine-readable ``code`` and a human-readable ``message`` that is
    safe to surface in API responses (no internal paths or stack traces).
    """

    ok: bool
    value: T | None = None
    error_code: str | None = None
    error_message: str | None = None

    @staticmethod
    def success(value: T) -> "RuntimeResult[T]":
        return RuntimeResult(ok=True, value=value)

    @staticmethod
    def failure(code: str, message: str) -> "RuntimeResult[T]":
        return RuntimeResult(ok=False, error_code=code, error_message=message)
