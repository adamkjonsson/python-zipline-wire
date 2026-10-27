"""What every transport's fidelity measurement shares.

The payloads, the scenario's fixed constants, packeteer's label grammar, and
where a frame sits in the capture a conversion is given, which is where a
citation points.  Depends on no transport.
"""

from __future__ import annotations

import hashlib
import re
from typing import Literal

Direction = Literal["c2s", "s2c"]
DIRECTIONS: tuple[Direction, Direction] = ("c2s", "s2c")

BASE_TIME = 1_700_000_000
"""Every scenario's first packet, in seconds.  packeteer's default is the
wall clock, which would make a seed reproduce everything but the timeline."""

BLOCK = 16
"""Bytes per position-unique payload block."""

CLIENT = ("10.0.0.1", 54321)
"""The client's address and port: a participant there sends ``c2s``."""


_KEY = b"zpfwire-fidelity"
_TOKEN = re.compile(r"([A-Z][A-Z-]*)(?:\[(.*)\])?$")


def payload(direction: Direction, message: int, length: int) -> bytes:
    """Return a message's bytes: 16-byte blocks keyed on their position.

    packeteer's default payload is repeating text, where a run written at the
    wrong offset can match the truth there.  Here each block is a keyed hash
    of its direction, message and block index, so it cannot — except by
    chance, one byte in 256, which the report states rather than hides.

    Args:
        direction: Which way the message travels.
        message: Its index in the scenario.
        length: How many bytes.

    Returns:
        The message's bytes.

    """
    blocks = (
        hashlib.blake2b(f"{direction}/{message}/{block}".encode(), key=_KEY,
                        digest_size=BLOCK).digest()
        for block in range(-(-length // BLOCK))
    )
    return b"".join(blocks)[:length]


def kinds_of(label: str) -> tuple[str, ...]:
    """Split a packeteer label into its kinds, outermost first.

    Args:
        label: E.g. ``DUP[CORRUPT[1] [5/7]]``, ``STRAY[0]``, ``FIN-ACK``.

    Returns:
        E.g. ``("DUP", "CORRUPT")``, ``("STRAY",)``, ``("FIN-ACK",)``.

    """
    kinds: list[str] = []
    rest: str | None = label
    while rest is not None and (match := _TOKEN.match(rest)):
        kinds.append(match.group(1))
        rest = match.group(2)
    assert kinds, f"unrecognised label {label!r}"
    return tuple(kinds)


# ── The capture ─────────────────────────────────────────────────────────

PCAP_HEADER = 24
"""Bytes before a pcap's first record, as packeteer writes one."""

PCAP_RECORD = 16
"""Bytes of a pcap record's header, before its frame."""


class Unclean(Exception):
    """A conversion that fails ``diagnostics == []`` and ``unplaceable == []``.

    Not scored: it is a bug in its own right.
    """
