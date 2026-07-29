#!/usr/bin/env python3
"""Deprecated fail-closed shim for the removed named-netns cleanup path."""

from __future__ import annotations

import sys
from typing import NoReturn


DEPRECATION_ERROR = (
    "named network namespace deletion is permanently disabled; "
    "the smoke test now owns anonymous namespace FDs and this compatibility "
    "shim performs no filesystem, process, iproute2, or network mutation"
)


class ContractError(RuntimeError):
    """Raised for every attempted use of the retired cleanup API."""


def delete_owned_netns(**_ignored: object) -> NoReturn:
    """Reject every legacy API call before inspecting paths or invoking hooks."""
    raise ContractError(DEPRECATION_ERROR)


def main() -> int:
    print(f"error: {DEPRECATION_ERROR}", file=sys.stderr)
    return 78


if __name__ == "__main__":
    raise SystemExit(main())
