"""Measure how well a conversion represents the traffic that was actually sent.

The ``0.7.0`` fidelity tool.  packeteer generates a TCP conversation under
impairments of our choosing and knows exactly what each application sent;
zpfwire converts the impaired capture; the tool scores the ``.zpf`` against
what was sent.  ``plans/V0.7.0-RELEASE-PLAN.md`` is the design.

This is Phase 1: **the truth and the ledger**, built from the generator alone.
Nothing here reads a ``.zpf``, and nothing here imports zpfwire — the ledger
is the reference the conversion is measured against, so it must not be
derived from the thing measured.

- :class:`Scenario` — messages by direction and size, a seed, and
  :class:`Impairments`.
- :class:`Truth` — each direction's messages, concatenated.  Payloads are
  position-unique, so a run written at the wrong offset cannot match.
- :class:`Ledger` — one :class:`Entry` per generated packet, the
  ranges (:class:`Segment`) the senders transmitted with their true send times, and
  the truth ranges no captured packet carries.
- :func:`self_check` — the conditions under which the run is not evidence
  about zpfwire at all, and is voided rather than scored.
"""

from __future__ import annotations

import dataclasses
import hashlib
import re
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Literal

from packeteer.generate.payloads.base import AppMessage
from packeteer.generate.tcp import TCP_FIN, TCP_RST, TCP_SYN
from packeteer.generate.tcp_stream import (
    TCPStream,
    TCPStreamConfig,
    TCPStreamPacket,
    generate_tcp_stream,
)
from packeteer.parse import parse_packet

Direction = Literal["c2s", "s2c"]
DIRECTIONS: tuple[Direction, Direction] = ("c2s", "s2c")

BASE_TIME = 1_700_000_000
"""Every scenario's first packet, in seconds.  packeteer's default is the
wall clock, which would make a seed reproduce everything but the timeline."""

BLOCK = 16
"""Bytes per position-unique payload block."""

_KEY = b"zpfwire-fidelity"
_WRAP = 2**32
_TOKEN = re.compile(r"([A-Z][A-Z-]*)(?:\[(.*)\])?$")

PROTOTYPE: tuple[tuple[Direction, int], ...] = (
    ("c2s", 3000), ("s2c", 9000), ("c2s", 800), ("s2c", 5000),
)
"""The prototype's four messages: a request and its response, twice."""


# ── The scenario ────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Impairments:
    """What the network does to a scenario, as packeteer configures it.

    Each field is the :class:`~packeteer.generate.tcp_stream.TCPStreamConfig`
    field of the same name, and means what it means there.  These are what
    was *configured*; what happened is the :class:`Ledger`'s to say.

    Attributes:
        packet_loss_probability: Chance a packet after the handshake is lost.
        retransmit_lost: Whether a lost segment is resent, so the stream
            recovers.
        retransmission_probability: Chance a delivered data segment is
            resent anyway.
        retransmission_timeout: Seconds before any resend.
        payload_corruption_probability: Chance a data segment's last byte is
            flipped in flight, and the segment resent clean.
        server_rst_probability: Chance the server resets mid-stream.
        rst_propagation_delay: Seconds before the client learns of the reset.
        stray_packet_count: Forged segments injected at real sequence numbers.
        stray_timing_window: How near its victim a stray is placed, in packets.
        duplicate_probability: Chance the capture point sees a packet twice.

    """

    packet_loss_probability: float = 0.0
    retransmit_lost: bool = False
    retransmission_probability: float = 0.0
    retransmission_timeout: float = 0.2
    payload_corruption_probability: float = 0.0
    server_rst_probability: float = 0.0
    rst_propagation_delay: float = 0.0
    stray_packet_count: int = 0
    stray_timing_window: int | None = None
    duplicate_probability: float = 0.0


@dataclass(frozen=True)
class Scenario:
    """One generated conversation: what is said, the seed, and the impairments.

    Attributes:
        shape: Each message's direction and length, in the order sent.
        seed: packeteer's seed.  Payloads do not depend on it.
        impairments: What the network does to it.

    """

    shape: tuple[tuple[Direction, int], ...] = PROTOTYPE
    seed: int = 0
    impairments: Impairments = Impairments()

    def messages(self) -> list[AppMessage]:
        """Return the messages, each payload position-unique.

        Returns:
            One :class:`~packeteer.generate.payloads.base.AppMessage` per
            entry of :attr:`shape`.

        """
        return [
            AppMessage(direction, payload(direction, index, length), f"m{index}")
            for index, (direction, length) in enumerate(self.shape)
        ]

    def generate(self) -> TCPStream:
        """Generate the impaired stream.

        Returns:
            packeteer's stream, deterministic in the scenario.

        """
        messages = self.messages()
        return generate_tcp_stream(
            client_ip="10.0.0.1", server_ip="10.0.0.2",
            # packeteer sends ``messages[i % len(messages)]`` for each of
            # ``num_data_packets``, so anything else would repeat or truncate.
            num_data_packets=len(messages),
            config=TCPStreamConfig(
                seed=self.seed, base_time=BASE_TIME, messages=messages,
                **dataclasses.asdict(self.impairments),
            ),
        )


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


# ── The truth ───────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Message:
    """Where one message sits in its direction's truth.

    Attributes:
        index: Its position in the scenario.
        direction: Which way it travels.
        offset: Its first byte's offset in that direction's truth.
        length: How many bytes.

    """

    index: int
    direction: Direction
    offset: int
    length: int


@dataclass(frozen=True)
class Truth:
    """What each application sent: its messages, concatenated.

    Independent of every impairment by construction — packeteer sends each
    message whole, and a sender's sequence number advances whether or not a
    segment arrives.  A server reset is the exception: the bytes after it
    were written but never sent, and :attr:`Ledger.sent` says where each
    sender stopped.

    Attributes:
        streams: Each direction's bytes.  Byte *k* is at stream offset *k*,
            where offset 0 is the sender's ISN plus one, as in a
            :class:`zpf.StreamView`.
        messages: Every message, in the order sent.

    """

    streams: dict[Direction, bytes]
    messages: tuple[Message, ...]

    @classmethod
    def of(cls, scenario: Scenario) -> Truth:
        """Build the truth for a scenario.

        Args:
            scenario: The scenario.

        Returns:
            Its truth.

        """
        streams: dict[Direction, bytearray] = {d: bytearray() for d in DIRECTIONS}
        messages = []
        for index, message in enumerate(scenario.messages()):
            stream = streams[message.direction]
            messages.append(Message(index, message.direction, len(stream), len(message.data)))
            stream += message.data
        return cls({d: bytes(s) for d, s in streams.items()}, tuple(messages))


# ── The ledger ──────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Entry:
    """One packet in the generated stream, as it relates to the truth.

    Attributes:
        index: Its position in ``stream.packets``, which is capture order.
        label: packeteer's label, e.g. ``DATA[1] [5/7]`` or ``DUP[RETRANS[2]]``.
        kinds: The label's kinds, outermost first: ``("DUP", "RETRANS")``.
            packeteer drops ``DATA`` from a label it derives, so ``RETRANS[2]``
            is a resend of a data segment and its kinds are ``("RETRANS",)``.
        direction: Which way it travels.
        flags: TCP flags as sent.
        seq: Sequence number as sent.
        offset: Its payload's first byte as a truth offset; for a segment
            without payload, where its sequence number falls.
        length: Payload bytes.
        usec: Capture time, in microseconds since the epoch.
        tsval: The TSval it carries, or ``None`` without a Timestamps option.
        checksum_ok: Whether its transport checksum verifies.
        matches: Whether its payload equals the truth at :attr:`offset`;
            ``None`` without payload.

    """

    index: int
    label: str
    kinds: tuple[str, ...]
    direction: Direction
    flags: int
    seq: int
    offset: int
    length: int
    usec: int
    tsval: int | None
    checksum_ok: bool
    matches: bool | None

    @property
    def kind(self) -> str:
        """The outermost kind: ``DATA``, ``RETRANS``, ``DUP``, ``CORRUPT`` and so on."""
        return self.kinds[0]

    @property
    def end(self) -> int:
        """The truth offset just past its payload."""
        return self.offset + self.length

    @property
    def stray(self) -> bool:
        """Whether a third party forged it."""
        return "STRAY" in self.kinds

    @property
    def corrupt(self) -> bool:
        """Whether it is, or copies, a segment corrupted in flight."""
        return "CORRUPT" in self.kinds

    @property
    def original(self) -> bool:
        """Whether it is a sender's first transmission of its bytes, as captured."""
        return self.length > 0 and self.kind in ("DATA", "CORRUPT")


@dataclass(frozen=True)
class Segment:
    """One range the sender transmitted, however many copies were captured.

    Attributes:
        direction: Which way it travels.
        offset: Its first byte's truth offset.
        length: How many bytes.
        sent_usec: Its true send time: the capture time of the original
            transmission, or ``None`` when the original was lost and only a
            resend was captured.  A resend is the same bytes, later.
        first_usec: When any captured copy of it was first seen.
        copies: The :attr:`Entry.index` of every captured, non-stray copy.

    """

    direction: Direction
    offset: int
    length: int
    sent_usec: int | None
    first_usec: int
    copies: tuple[int, ...]


@dataclass(frozen=True)
class Ledger:
    """What happened to every byte the scenario sent.

    Attributes:
        entries: One per packet in ``stream.packets``, in capture order.
        isn: Each direction's initial sequence number, from its SYN.
        segments: Each sender's transmitted ranges, by direction and offset.
        reset: Whether a server RST was captured.
        sent: How much of each direction's truth its sender sent: all of it,
            unless the connection was reset, when it is the furthest byte
            any captured segment carries.  packeteer removes everything a
            side would have sent after it learned of the reset, so that is
            exact unless the last segment before it was also lost on the
            wire, which this counts as unsent.
        lost: Each direction's ranges, ``(start, end)``, that were sent and
            that no captured non-stray packet carries: lost on the wire, and
            not resent or not resent in time to be captured.

    """

    entries: tuple[Entry, ...]
    isn: dict[Direction, int]
    segments: tuple[Segment, ...]
    reset: bool
    sent: dict[Direction, int]
    lost: dict[Direction, tuple[tuple[int, int], ...]]

    @classmethod
    def of(cls, stream: TCPStream, truth: Truth) -> Ledger:
        """Build the ledger of a generated stream against its truth.

        Args:
            stream: packeteer's stream.
            truth: The scenario's truth.

        Returns:
            Its ledger.

        """
        isn: dict[Direction, int] = {}
        for packet in stream.packets:
            if packet.flags & TCP_SYN:
                isn.setdefault(_direction(packet), packet.seq)
        entries = tuple(
            _entry(index, packet, isn, truth) for index, packet in enumerate(stream.packets)
        )
        reset = any(e.flags & TCP_RST for e in entries)
        sent = {d: len(truth.streams[d]) for d in DIRECTIONS}
        if reset:
            for d in DIRECTIONS:
                sent[d] = max((e.end for e in entries
                               if e.direction == d and e.length and not e.stray), default=0)
        return cls(
            entries=entries,
            isn=isn,
            segments=_segments(entries),
            reset=reset,
            sent=sent,
            lost={d: _uncovered(entries, d, sent[d]) for d in DIRECTIONS},
        )

    def kinds(self) -> dict[str, int]:
        """Count the entries by outermost kind: what the run realised.

        Returns:
            ``{kind: count}``.  A lost segment is not an entry; see
            :attr:`lost`.

        """
        counts: dict[str, int] = {}
        for entry in self.entries:
            counts[entry.kind] = counts.get(entry.kind, 0) + 1
        return counts

    def data(self, direction: Direction | None = None) -> Iterator[Entry]:
        """Yield the entries carrying payload, optionally in one direction.

        Args:
            direction: Only this direction, or both when ``None``.

        Yields:
            Each payload-carrying entry, in capture order.

        """
        for entry in self.entries:
            if entry.length and direction in (None, entry.direction):
                yield entry


def _direction(packet: TCPStreamPacket) -> Direction:
    assert packet.direction in DIRECTIONS, packet.direction
    return packet.direction  # type: ignore[return-value]


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


def _entry(
    index: int, packet: TCPStreamPacket, isn: dict[Direction, int], truth: Truth,
) -> Entry:
    direction = _direction(packet)
    parsed = parse_packet(packet.raw, decode_app=False)
    assert parsed.transport is not None, f"packet {index} ({packet.label}) has no transport"
    body = parsed.payload
    assert len(body) == packet.payload_len, (index, packet.label)
    offset = (packet.seq - isn[direction] - 1) % _WRAP
    if packet.flags & TCP_SYN:
        offset = -1
    expected = truth.streams[direction][offset:offset + len(body)] if body else None
    return Entry(
        index=index,
        label=packet.label,
        kinds=kinds_of(packet.label),
        direction=direction,
        flags=packet.flags,
        seq=packet.seq,
        offset=offset,
        length=len(body),
        usec=packet.ts_sec * 1_000_000 + packet.ts_usec,
        tsval=packet.timestamps[0] if packet.timestamps is not None else None,
        # packeteer keeps a parsed checksum only where the bytes beside it do
        # not produce it (packeteer#68); nothing here is truncated.
        checksum_ok=parsed.transport.checksum is None,
        matches=None if expected is None else expected == body,
    )


def _segments(entries: tuple[Entry, ...]) -> tuple[Segment, ...]:
    copies: dict[tuple[Direction, int, int], list[Entry]] = {}
    for entry in entries:
        if entry.length and not entry.stray:
            copies.setdefault((entry.direction, entry.offset, entry.length), []).append(entry)
    segments = []
    for (direction, offset, length), seen in sorted(copies.items()):
        originals = [e.usec for e in seen if e.original]
        segments.append(Segment(
            direction=direction, offset=offset, length=length,
            sent_usec=min(originals) if originals else None,
            first_usec=min(e.usec for e in seen),
            copies=tuple(e.index for e in seen),
        ))
    return tuple(segments)


def _uncovered(
    entries: tuple[Entry, ...], direction: Direction, length: int,
) -> tuple[tuple[int, int], ...]:
    covered = sorted(
        (e.offset, e.end) for e in entries
        if e.direction == direction and e.length and not e.stray
    )
    holes = []
    edge = 0
    for start, end in covered:
        if start > edge:
            holes.append((edge, min(start, length)))
        edge = max(edge, end)
    if edge < length:
        holes.append((edge, length))
    return tuple(hole for hole in holes if hole[0] < hole[1])


# ── Self-checks ─────────────────────────────────────────────────────────


def self_check(truth: Truth, ledger: Ledger) -> list[str]:
    """Return why the run is not evidence about the conversion, if it is not.

    A run that fails any of these is **void**: it is reported, never scored.
    Each says the generator did not produce what the truth and ledger claim,
    so a score would measure packeteer rather than zpfwire.

    Args:
        truth: The scenario's truth.
        ledger: Its ledger.

    Returns:
        One line per failure; empty when the run may be scored.

    """
    failures = []
    for entry in ledger.entries:
        # packeteer#227: rebuilding a corrupted segment to fix its
        # acknowledgement recomputes its checksum, so the receiver — and
        # ``checksum="drop"`` — would accept the corrupted bytes.
        if entry.corrupt and entry.checksum_ok:
            failures.append(
                f"packeteer#227: {entry.label} (packet {entry.index}) is corrupt "
                f"and its checksum verifies"
            )
        if entry.kind == "DATA" and entry.length and not entry.matches:
            failures.append(
                f"{entry.label} (packet {entry.index}) does not carry the truth "
                f"at offset {entry.offset}"
            )
    for direction in DIRECTIONS:
        length = len(truth.streams[direction])
        sent = sum(m.length for m in truth.messages if m.direction == direction)
        if length != sent:
            failures.append(f"{direction}: the truth is {length} bytes, its messages {sent}")
        for entry in ledger.data(direction):
            if not entry.stray and entry.end > length:
                failures.append(
                    f"{direction}: {entry.label} (packet {entry.index}) ends at "
                    f"{entry.end}, past the truth's {length}"
                )
        for entry in ledger.entries:
            if entry.direction == direction and entry.flags & TCP_FIN and entry.offset != length:
                failures.append(
                    f"{direction}: {entry.label} (packet {entry.index}) is at "
                    f"{entry.offset}, not the truth's end {length}"
                )
    return failures


# ── A run ───────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Run:
    """A generated scenario, ready to convert and score.

    Attributes:
        scenario: What was asked for.
        stream: What packeteer generated.
        truth: What was sent.
        ledger: What happened to it.
        void: Why the run may not be scored; empty when it may.

    """

    scenario: Scenario
    stream: TCPStream
    truth: Truth
    ledger: Ledger
    void: tuple[str, ...]


def run(scenario: Scenario) -> Run:
    """Generate a scenario and build its truth, ledger and self-checks.

    Args:
        scenario: The scenario.

    Returns:
        The run.

    """
    stream = scenario.generate()
    truth = Truth.of(scenario)
    ledger = Ledger.of(stream, truth)
    return Run(scenario, stream, truth, ledger, tuple(self_check(truth, ledger)))
