"""Conversion options, and the digest that makes a conversion reproducible."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from importlib.metadata import PackageNotFoundError, version

__all__ = [
    "CHECKSUM_POLICIES",
    "DECODER_NAME",
    "OVERLAP_POLICIES",
    "ReassemblyOptions",
    "tool_version",
]

DECODER_NAME = "tcp-reassembly"
"""Name recorded on the Decoder Descriptor for the reassembly stage."""

OVERLAP_POLICIES = ("favor-old", "favor-new")
"""How to resolve bytes that arrive twice with differing content."""

CHECKSUM_POLICIES = ("ignore", "drop")
"""What to do with a packet whose transport checksum does not verify."""


def tool_version() -> str:
    """Return this package's version, or ``"unknown"`` outside an install."""
    try:
        return version("zpfwire")
    except PackageNotFoundError:
        return "unknown"


@dataclass(frozen=True)
class ReassemblyOptions:
    """Policy for turning TCP segments into records.

    These are not tuning knobs in the usual sense: together they decide which
    bytes reach the output and which are thrown away. The specification makes
    committing a gap irreversible — once a record has been written past
    missing bytes, those bytes may never be written, even if they arrive later
    — so :attr:`reorder_window` and :attr:`flush_timeout` set how long the
    reassembler is willing to wait before making that call.

    That is why the whole set is hashed into :meth:`params_digest` and
    recorded on the Decoder Descriptor: it is what makes a conversion
    reproducible, and what tells a later reader why bytes are missing.

    Attributes:
        overlap: Which copy wins when retransmitted bytes disagree with bytes
            already accepted. ``"favor-old"`` keeps what was seen first, as
            most receiving stacks do.
        reorder_window: Bytes a direction may hold out of order before the
            oldest gap is committed. ``0`` disables buffering entirely.
        flush_timeout: Seconds a gap may stay unfilled, measured in capture
            time, before it is committed.
        session_timeout: Seconds of silence after which a session is closed
            with reason ``"timeout"``.
        coalesce: Join contiguous segments into one record, flushing on PSH
            and at every boundary. When ``False``, each segment becomes its
            own record.
        checksum: What to do with a packet whose transport checksum does not
            verify. A receiver discards it and takes the retransmission that
            follows, which is what ``"drop"`` does; ``"ignore"`` converts it
            anyway. The default is ``"ignore"`` because checksum offload makes
            a capture taken on a sending host report wrong checksums for
            traffic that was correct on the wire — dropping those by default
            would gut such a capture.

    """

    overlap: str = "favor-old"
    reorder_window: int = 262_144
    flush_timeout: float = 5.0
    session_timeout: float = 300.0
    coalesce: bool = True
    checksum: str = "ignore"

    def __post_init__(self) -> None:
        """Validate the policy.

        Raises:
            ValueError: If any value is outside its permitted range.

        """
        if self.overlap not in OVERLAP_POLICIES:
            raise ValueError(
                f"overlap must be one of {', '.join(OVERLAP_POLICIES)}, got {self.overlap!r}",
            )
        if self.reorder_window < 0:
            raise ValueError("reorder_window must not be negative")
        if self.flush_timeout < 0:
            raise ValueError("flush_timeout must not be negative")
        if self.session_timeout < 0:
            raise ValueError("session_timeout must not be negative")
        if self.checksum not in CHECKSUM_POLICIES:
            raise ValueError(
                f"checksum must be one of {', '.join(CHECKSUM_POLICIES)}, "
                f"got {self.checksum!r}",
            )

    def params_digest(self) -> str:
        """Return a stable ``sha256:`` digest of this policy.

        The specification's reproducibility contract is *same input digest +
        same decoder version and params digest ⇒ identical output*, so this
        must depend on every field that can change the bytes written.

        Returns:
            A digest string such as ``"sha256:1f3a…"``.

        """
        canonical = json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))
        return "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()
