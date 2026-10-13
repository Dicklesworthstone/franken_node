"""Bounded deletion searches for captured migration inputs.

This module performs no I/O and grants no execution authority. The caller owns
input authentication, execution/cancellation budgets, repeated confirmation of
ALL recorded observations, and publication. An oracle rejection never becomes
a successful reduction. Neither search claims a global or grammar-level minimum.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TypeVar

MAX_REDUCTION_BYTES = 1024 * 1024
MAX_CANDIDATES = 4096
Sequence = TypeVar("Sequence", str, bytes)


class CandidateBudgetExceeded(Exception):
    """Keep the caller's last accepted state; never publish an untested candidate."""


def _delete_complements(value: Sequence, interesting: Callable[[Sequence], bool],
                        max_candidates: int) -> Sequence:
    if type(max_candidates) is not int or not 1 <= max_candidates <= MAX_CANDIDATES:
        raise ValueError("candidate limit must be an integer between 1 and 4096")
    attempts = 0

    def check(candidate: Sequence) -> bool:
        nonlocal attempts
        if attempts >= max_candidates:
            raise CandidateBudgetExceeded("candidate_partition_budget")
        attempts += 1
        accepted = interesting(candidate)
        if type(accepted) is not bool:
            raise TypeError("reduction oracle must return a boolean")
        return accepted

    # Empty can be interesting even when neither half is interesting. Check it
    # explicitly, once. The initial value itself is already admitted by caller.
    if not value:
        return value
    if check(value[:0]):
        return value[:0]
    current = value
    granularity = min(2, len(current))
    while current:
        reduced = False
        for part in range(granularity):
            start = part * len(current) // granularity
            end = (part + 1) * len(current) // granularity
            candidate = current[:start] + current[end:]
            if not candidate:  # Already checked above for this exact value.
                continue
            if check(candidate):
                current = candidate
                granularity = min(len(current), max(2, granularity - 1))
                reduced = True
                break
        if not reduced:
            if granularity == len(current):
                break
            granularity = min(len(current), granularity * 2)
    return current


def _bounded_bytes(data: bytes) -> None:
    if type(data) is not bytes or len(data) > MAX_REDUCTION_BYTES:
        raise ValueError("reduction input must be bytes of at most 1 MiB")


def reduce_utf8(data: bytes, interesting: Callable[[bytes], bool], *,
                max_candidates: int = MAX_CANDIDATES) -> bytes:
    """Delete contiguous Unicode-scalar spans, including inside one-line sources.

    No parser, formatting, normalization, replacement literals or host code
    evaluation is used. Source text always round-trips as strict UTF-8. Deleted
    spans can break JavaScript syntax; the execution oracle must reject those
    candidates, not treat a new parse error as the original failure. Slicing a
    string avoids allocating a per-character list for a 1 MiB minified file.
    Exceptions, including caller cancellation/budget stops, propagate unchanged.
    """
    _bounded_bytes(data)
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeError:
        raise ValueError("source reduction requires valid UTF-8") from None
    return _delete_complements(text, lambda value: interesting(value.encode("utf-8")),
                               max_candidates).encode("utf-8")
