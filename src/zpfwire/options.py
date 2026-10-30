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

OVERLAP_POLICIES = ("favor-old", "favor-acked")
"""How to resolve bytes that arrive twice with differing content.

``favor-old`` keeps the first copy seen, which is what a single-pass writer
can always do.  ``favor-acked`` keeps the copy the *receiver* kept, read
from the TSecr on the peer's first acknowledgement covering the range — the
TCP Timestamps option echoes the TSval of the transmission that advanced
the window.  That evidence arrives after both copies, so every run is held
after it closes until the peer's ack covers it, bounded by ``flush_timeout``
and ``reorder_window``; where the evidence never comes the run is written as
``favor-old`` would have written it, and the fallback is counted.

A ``favor-new`` was offered until 0.2.0 and never read, for the reason that
makes ``favor-acked`` need the hold: a writer cannot prefer a later copy
against bytes it has already written.  It stays withdrawn — "the later
copy" is not a fact about the connection, and "the copy the receiver kept"
is.  See :attr:`ReassemblyOptions.overlap`.
"""

CHECKSUM_POLICIES = ("ignore", "drop")
"""What to do with a TCP segment whose checksum does not verify; UDP is always kept."""


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
            most receiving stacks do, and is what a single pass can always
            keep: once a record has been written, a later copy of its bytes
            cannot replace them.  ``"favor-acked"`` keeps the copy the
            receiver kept, by holding each run until the peer's ack covers
            it and reading the Timestamps echo; see :data:`OVERLAP_POLICIES`
            and :attr:`acked_hold`.
        reorder_window: Bytes a direction may hold out of order before the
            oldest gap is committed. ``0`` disables buffering entirely.
        flush_timeout: Seconds a gap may stay unfilled, measured in capture
            time, before it is committed.
        session_timeout: Seconds of silence after which a session is closed
            with reason ``"timeout"``.
        coalesce: Join contiguous segments into one record, ending it where
            a segment's PSH says, in sequence order, where the peer's data
            answers it, and at every boundary. When ``False``, each segment
            becomes its own record, including those drained from the
            reorder buffer.
        checksum: What to do with a TCP segment whose checksum does not
            verify. A receiver discards it and takes the retransmission that
            follows, which is what ``"drop"`` does; ``"ignore"`` converts it
            anyway. The default is ``"ignore"`` because checksum offload makes
            a capture taken on a sending host report wrong checksums for
            traffic that was correct on the wire — dropping those by default
            would gut such a capture. A **UDP** datagram is kept under either
            policy, and counted: a UDP stream's offsets are not
            sequence-anchored, so a datagram left out would leave no trace in
            it, and the specification forbids a transport-layer stage to
            withhold content from such a stream.
        pure_acks: Store each TCP segment that carries neither bytes nor a
            SYN, FIN or RST as a zero-length record holding its ``ack``, as
            the specification advises since ``0.23``. A pure ACK has no end,
            so no edge runs from it, but its ``ack`` places it after the peer
            bytes it covers: the causal merge gets an edge for every one, the
            receiver's reaction times are in the file, and a ``.zpf`` input
            cites the packet instead of leaving it ``skipped``. It costs a
            record per pure ACK, and there are about as many pure ACKs as
            data segments: on a 4,140-packet HTTP capture, 23% more output
            and about 20% more conversion time, mostly the ``zpf`` writer's
            per-record work. A cost paid once when writing, for information
            every reader gets, since a file is read far more often than
            written. ``False`` folds each ``ack`` into the next data record
            instead, which is what every release before ``0.6.0`` did, and
            writes exactly what ``0.5.0`` wrote; see :meth:`params_digest`.
        acked_hold: Under ``overlap="favor-acked"``, seconds a closed run may
            wait for the receiver's covering ack before it is written on the
            fallback.  ``None``, the default, bounds the hold by
            :attr:`flush_timeout` and :attr:`reorder_window`, which is right
            while a resend arrives within them.  A path whose resend comes
            later — a bulk transfer behind an initial RTO of a second, a
            delayed-ACK stack under load — releases runs before their
            contest, and every such byte is counted in
            ``acked_fallback_bytes`` (#32).  Set, it is the hold's only
            bound, so the memory it takes is the traffic it spans.
        require_timestamps: Drop a TCP segment that lacks the Timestamps
            option on a connection whose two SYNs both carried it, as RFC
            7323 §3.2 has a receiver do: bytes, ack and flags, cited as
            ``timestamp-missing``.  A segment forged by a third party usually
            lacks the option, so this keeps strays out of the stream.  Off by
            default, because a middlebox that strips options mid-connection
            would make it drop real data; a capture that began after the
            handshake never applies it (#57).

    """

    overlap: str = "favor-old"
    reorder_window: int = 262_144
    flush_timeout: float = 5.0
    session_timeout: float = 300.0
    coalesce: bool = True
    checksum: str = "ignore"
    pure_acks: bool = True
    acked_hold: float | None = None
    require_timestamps: bool = False

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
        if self.acked_hold is not None and self.acked_hold < 0:
            raise ValueError("acked_hold must not be negative")
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

        :attr:`pure_acks` is left out when it is ``False``, which is the
        behaviour of every release before it existed.  So a conversion that
        opts out declares the digest ``0.5.0`` declared for the same policy,
        as well as writing the same bytes, and one that does not is told
        apart by its digest.  :attr:`acked_hold` is left out when it is
        ``None``, and :attr:`require_timestamps` when it is ``False``, on
        the same rule: a policy that does not set them declares the digest it
        declared before the fields existed (#32, #57).

        Returns:
            A digest string such as ``"sha256:1f3a…"``.

        """
        policy = asdict(self)
        if not self.pure_acks:
            del policy["pure_acks"]
        if self.acked_hold is None:
            del policy["acked_hold"]
        if not self.require_timestamps:
            del policy["require_timestamps"]
        canonical = json.dumps(policy, sort_keys=True, separators=(",", ":"))
        return "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()
