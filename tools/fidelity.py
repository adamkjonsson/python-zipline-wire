"""Measure how well a conversion represents the traffic that was actually sent.

The ``0.7.0`` fidelity tool.  packeteer generates a TCP conversation under
impairments of our choosing and knows exactly what each application sent;
zpfwire converts the impaired capture; the tool scores the ``.zpf`` against
what was sent.  ``plans/V0.7.0-RELEASE-PLAN.md`` is the design.

**The truth and the ledger** (Phase 1) are built from the generator alone.
They never consult zpfwire: they are the reference the conversion is
measured against, so they must not be derived from the thing measured.

- :class:`Scenario` — messages by direction and size, a seed, and
  :class:`Impairments`.
- :class:`Truth` — each direction's messages, concatenated.  Payloads are
  position-unique, so a run written at the wrong offset cannot match.
- :class:`Ledger` — one :class:`Entry` per generated packet, the
  ranges (:class:`Segment`) the senders transmitted with their true send times, and
  the truth ranges no captured packet carries.
- :func:`self_check` — the conditions under which the run is not evidence
  about zpfwire at all, and is voided rather than scored.

**The byte scorer** (Phase 2) converts the run and reads the file back
through zpf's public reader only.

- :func:`measure` — convert, read back, score.  A file that fails this
  project's load-bearing assertion raises :class:`Unclean` rather than
  scoring.
- :class:`ByteScore` — every sent offset is correct, substituted, missing
  inside a ``Gap``, or missing past the end; with *fidelity* against what
  was sent, *recovery* against what was captured, and each error attributed
  to its cause.
- :class:`Accounting` — whether the file and its stats tell the truth about
  themselves: every uncited captured byte in exactly one record, the gap
  count, the duplicate-or-resend judgement, the end reason.
"""

from __future__ import annotations

import bisect
import dataclasses
import hashlib
import io
import re
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Literal

import zpf
from packeteer.generate.payloads.base import AppMessage
from packeteer.generate.tcp import TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN
from packeteer.generate.tcp_stream import (
    TCPStream,
    TCPStreamConfig,
    TCPStreamPacket,
    generate_tcp_stream,
)
from packeteer.parse import parse_packet
from packeteer.pcap import write_pcap

from zpfwire import ConversionStats, ReassemblyOptions, capture_to_zpf

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
        psh_probability: The chance a message's last segment carries PSH,
            drawn once per message.  packeteer's default, 0.5, leaves half
            the messages unpushed; a real stack pushes at the end of nearly
            every write.  Not an impairment — what the sender does — and it
            matters, since zpfwire ends a coalesced run at PSH.

    """

    shape: tuple[tuple[Direction, int], ...] = PROTOTYPE
    seed: int = 0
    impairments: Impairments = Impairments()
    psh_probability: float = 0.5

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
            client_ip=CLIENT[0], client_port=CLIENT[1], server_ip="10.0.0.2",
            # packeteer sends ``messages[i % len(messages)]`` for each of
            # ``num_data_packets``, so anything else would repeat or truncate.
            num_data_packets=len(messages),
            config=TCPStreamConfig(
                seed=self.seed, base_time=BASE_TIME, messages=messages,
                psh_probability=self.psh_probability,
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
        payload: Its payload bytes.
        payload_at: Where its payload starts in its frame.
        acked: How much of the peer's truth it acknowledges, as an offset
            in the peer's stream: every peer byte before it had arrived.
            ``None`` without the ACK flag, or before the peer's SYN.

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
    payload: bytes = dataclasses.field(default=b"", repr=False)
    payload_at: int = dataclasses.field(default=0, repr=False)
    acked: int | None = None

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
        sent: dict[Direction, int] = {d: len(truth.streams[d]) for d in DIRECTIONS}
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
    peer: Direction = "s2c" if direction == "c2s" else "c2s"
    acked = None
    if packet.flags & TCP_ACK and peer in isn:
        acked = (packet.ack - isn[peer] - 1) % _WRAP
        if acked >= _WRAP // 2:  # the ack of a SYN: nothing of the stream yet
            acked = 0
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
        payload=body,
        payload_at=parsed.payload_offset or 0,
        acked=acked,
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


# ── Converting and reading back ─────────────────────────────────────────

_PCAP_HEADER = 24
_PCAP_RECORD = 16


class Unclean(Exception):
    """A conversion that fails ``diagnostics == []`` and ``unplaceable == []``.

    Not scored: it is a bug in its own right.
    """


@dataclass(frozen=True)
class Output:
    """What a reader of the converted file gets, by direction.

    Attributes:
        chunks: Each direction's :meth:`zpf.StreamView.chunks`.
        records: Each direction's records with payload, as ``(offset,
            record)``, the offset relative to the participant's ISN plus one.
        undecoded: Every Undecoded block, as ``(start, end, reason)`` in
            capture-file bytes.
        end_reason: The session's end reason.
        sessions: How many sessions the file holds; a run is one connection.
        timeline: The records with payload in :meth:`zpf.SessionReader.timeline`
            order — stored order for a sequenced session, the causal merge
            otherwise — as ``(direction, offset, record)``.
        tick_hz: The file's ticks per second.
        epoch: The file's ``time_epoch``, in ticks.

    """

    chunks: dict[Direction, tuple[zpf.Segment | zpf.Gap, ...]]
    records: dict[Direction, tuple[tuple[int, zpf.Record], ...]]
    undecoded: tuple[tuple[int, int, str], ...]
    end_reason: str | None
    sessions: int
    timeline: tuple[tuple[Direction, int, zpf.Record], ...] = ()
    tick_hz: int = 1_000_000
    epoch: int = 0

    def usec(self, ticks: int) -> int:
        """Return a record time as microseconds since the Unix epoch, as the ledger keeps them.

        Args:
            ticks: A record's ``timestamp`` or ``ts_first``.

        Returns:
            The same instant in microseconds.

        """
        return (self.epoch + ticks) * 1_000_000 // self.tick_hz


@dataclass(frozen=True)
class Conversion:
    """One run converted under one policy.

    Attributes:
        options: The reassembly policy.
        sequenced: Whether the session was written in causal order.
        stats: What the conversion reported.
        output: What the file holds.
        data: The file itself.

    """

    options: ReassemblyOptions
    sequenced: bool
    stats: ConversionStats
    output: Output
    data: bytes = dataclasses.field(default=b"", repr=False)


def convert(
    stream: TCPStream,
    options: ReassemblyOptions | None = None,
    *,
    sequenced: bool = False,
    face: Literal["binary", "jsonl"] = "binary",
) -> Conversion:
    """Convert a generated stream in memory and read the file back.

    Args:
        stream: The stream, usually a :attr:`Run.stream`.
        options: The reassembly policy; zpfwire's defaults when ``None``.
        sequenced: Whether to write the session in causal order.
        face: The file's face.  JSONL is one block per line, which is what
            lets a test reorder records by hand.

    Returns:
        The conversion.

    Raises:
        Unclean: If the file does not read back clean.

    """
    options = options or ReassemblyOptions()
    capture = io.BytesIO()
    write_pcap(stream.to_pcap_tuples(), file_object=capture)
    capture.seek(0)
    # The JSONL face is written to a text stream; zpf reads it back from bytes.
    sink = io.StringIO() if face == "jsonl" else io.BytesIO()
    stats = capture_to_zpf(capture, sink, options=options, sequenced=sequenced,
                           face=face, produced_at=None)
    value = sink.getvalue()
    data = value.encode() if isinstance(value, str) else value
    return Conversion(options, sequenced, stats, read(data), data)


def read(data: bytes) -> Output:
    """Read a converted file through zpf's public reader.

    Args:
        data: The ``.zpf`` file's bytes.

    Returns:
        What it holds.

    Raises:
        Unclean: If it does not read back clean.

    """
    chunks: dict[Direction, tuple[zpf.Segment | zpf.Gap, ...]] = dict.fromkeys(DIRECTIONS, ())
    records: dict[Direction, tuple[tuple[int, zpf.Record], ...]] = dict.fromkeys(DIRECTIONS, ())
    timeline: list[tuple[Direction, int, zpf.Record]] = []
    with zpf.open(io.BytesIO(data)) as reader:
        sessions = reader.sessions()
        end_reason = None
        for session in sessions:
            end_reason = session.end.reason if session.end else None
            for _ in session.records():
                pass
            origins: dict[int, tuple[Direction, int]] = {}
            for view in session.reassemble():
                participant = view.participant
                direction: Direction = (
                    "c2s" if participant.endpoint == "{}:{}".format(*CLIENT) else "s2c"
                )
                assert participant.isn is not None, participant
                origins[participant.participant_id] = (direction, participant.isn)
                chunks[direction] += tuple(view.chunks())
                records[direction] += tuple(
                    ((r.seq_start - participant.isn - 1) % _WRAP, r)
                    for r in session.stream(participant.participant_id)
                    if r.payload and r.seq_start is not None
                )
            for record in session.timeline():
                if record.payload and record.seq_start is not None:
                    direction, isn = origins[record.sender_pid]
                    timeline.append((direction, (record.seq_start - isn - 1) % _WRAP, record))
        if reader.diagnostics or reader.unplaceable:
            raise Unclean(f"diagnostics {reader.diagnostics}, unplaceable {reader.unplaceable}")
        undecoded = tuple((u.off_start, u.off_end, u.reason or "") for u in reader.undecoded)
        header = reader.header
        assert header is not None, "a file read to the end has a header"
        tick_hz, epoch = header.tick_hz, header.time_epoch or 0
    return Output(chunks, records, undecoded, end_reason, len(sessions),
                  tuple(timeline), tick_hz, epoch)


# ── The byte scorer ─────────────────────────────────────────────────────


@dataclass(frozen=True)
class ByteScore:
    """Every offset a sender sent, classified by what the file holds there.

    Per direction, every offset in ``[0, sent)`` is exactly one of correct,
    substituted, missing inside a ``Gap``, or missing past the end.  The
    last needs the truth: ``chunks()`` never yields a trailing ``Gap``.

    Attributes:
        sent: Bytes the sender sent (:attr:`Ledger.sent`).
        correct: Offsets holding the true byte.
        substituted: Offsets holding a different byte.
        missing_declared: Offsets inside a ``Gap``.
        missing_past_end: Offsets past the last ``Segment``.
        extra: Output bytes at or past ``sent``.
        available: Offsets where some captured, non-stray packet carries the
            true byte: the ceiling a reassembler could reach.
        causes: Bytes by error and cause.  ``substituted:stray`` and
            ``substituted:corrupt`` are bytes a forged or damaged copy put
            there; ``substituted:other`` matches no captured copy and is a
            bug.  ``missing:lost`` is a range no non-stray packet carried;
            ``missing:dropped`` one that some packet did.

    """

    sent: int
    correct: int
    substituted: int
    missing_declared: int
    missing_past_end: int
    extra: int
    available: int
    causes: dict[str, int]

    def __add__(self, other: ByteScore) -> ByteScore:
        """Add two scores, as both directions of a run or many runs of a cell."""
        causes = dict(self.causes)
        for cause, count in other.causes.items():
            causes[cause] = causes.get(cause, 0) + count
        return ByteScore(
            sent=self.sent + other.sent,
            correct=self.correct + other.correct,
            substituted=self.substituted + other.substituted,
            missing_declared=self.missing_declared + other.missing_declared,
            missing_past_end=self.missing_past_end + other.missing_past_end,
            extra=self.extra + other.extra,
            available=self.available + other.available,
            causes=causes,
        )

    @property
    def fidelity(self) -> float:
        """Correct over sent: what a reader of the file gets."""
        return self.correct / self.sent if self.sent else 1.0

    @property
    def recovery(self) -> float:
        """Correct over available: what the reassembler made of what it was given."""
        return self.correct / self.available if self.available else 1.0


def score_bytes(run: Run, output: Output, direction: Direction) -> ByteScore:
    """Score one direction of a converted run against its truth.

    Args:
        run: The run.
        output: What its conversion holds.
        direction: Which direction to score.

    Returns:
        The direction's score.

    """
    truth = run.truth.streams[direction]
    sent = run.ledger.sent[direction]
    held = bytearray(sent)
    have = bytearray(sent)
    declared = bytearray(sent)
    extra = 0
    end = 0
    substituted: list[tuple[int, int]] = []
    correct = 0
    for chunk in output.chunks[direction]:
        start, stop = min(chunk.off_start, sent), min(chunk.off_end, sent)
        if isinstance(chunk, zpf.Gap):
            declared[start:stop] = b"\x01" * (stop - start)
            continue
        end = max(end, chunk.off_end)
        extra += chunk.off_end - max(chunk.off_start, sent)
        data = chunk.data[:stop - start]
        held[start:stop] = data
        have[start:stop] = b"\x01" * (stop - start)
        good, wrong = _compare(data, truth, start)
        correct += good
        substituted += wrong

    covered, available = _coverage(run.ledger, truth, direction, sent)
    present = have.count(1)
    missing_declared = declared.count(1)
    past_end = sent - min(end, sent)
    assert present + missing_declared + past_end == sent, "a hole that is not a Gap"

    causes = {"missing:lost": 0, "missing:dropped": 0}
    for start, stop in _runs(declared) + ([(end, sent)] if past_end else []):
        carried = covered[start:stop].count(1)
        causes["missing:lost"] += (stop - start) - carried
        causes["missing:dropped"] += carried
    for offset, value in substituted:
        cause = _substitute_cause(run.ledger, direction, offset, value)
        causes[f"substituted:{cause}"] = causes.get(f"substituted:{cause}", 0) + 1
    return ByteScore(
        sent=sent,
        correct=correct,
        substituted=len(substituted),
        missing_declared=missing_declared,
        missing_past_end=past_end,
        extra=max(extra, 0),
        available=available.count(1),
        causes={cause: count for cause, count in causes.items() if count},
    )


def _compare(data: bytes, truth: bytes, start: int) -> tuple[int, list[tuple[int, int]]]:
    """Count the bytes of *data* equal to *truth* at *start*, and list the others."""
    good = 0
    wrong = []
    step = 4096
    for at in range(0, len(data), step):
        piece = data[at:at + step]
        if piece == truth[start + at:start + at + len(piece)]:
            good += len(piece)
            continue
        for i, value in enumerate(piece):
            if value == truth[start + at + i]:
                good += 1
            else:
                wrong.append((start + at + i, value))
    return good, wrong


def _coverage(
    ledger: Ledger, truth: bytes, direction: Direction, sent: int,
) -> tuple[bytearray, bytearray]:
    """Mark where captured non-stray packets carry anything, and the true byte."""
    covered = bytearray(sent)
    available = bytearray(sent)
    for entry in ledger.data(direction):
        if entry.stray:
            continue
        start, stop = min(entry.offset, sent), min(entry.end, sent)
        covered[start:stop] = b"\x01" * (stop - start)
        if entry.matches:
            available[start:stop] = b"\x01" * (stop - start)
            continue
        for i in range(start, stop):
            if entry.payload[i - entry.offset] == truth[i]:
                available[i] = 1
    return covered, available


def _runs(mask: bytearray) -> list[tuple[int, int]]:
    """Return the ``(start, end)`` runs of set bytes in *mask*."""
    runs = []
    at = mask.find(1)
    while at != -1:
        stop = mask.find(0, at)
        stop = len(mask) if stop == -1 else stop
        runs.append((at, stop))
        at = mask.find(1, stop)
    return runs


def _substitute_cause(ledger: Ledger, direction: Direction, offset: int, value: int) -> str:
    """Name the captured copy that put *value* at *offset*: ``stray``, ``corrupt`` or ``other``."""
    carriers = [
        e for e in ledger.data(direction)
        if e.offset <= offset < e.end and e.payload[offset - e.offset] == value
    ]
    if any(e.stray for e in carriers):
        return "stray"
    if any(e.corrupt for e in carriers):
        return "corrupt"
    return "other"


# ── Accounting ──────────────────────────────────────────────────────────

REASON_DUPLICATE = "duplicate-discarded"
"""zpfwire's Undecoded reason for a copy of one transmission."""


@dataclass(frozen=True)
class Accounting:
    """Whether the file and its stats tell the truth about themselves.

    Attributes:
        quiet: Captured payload bytes in no record and cited by no
            Undecoded block: lost quietly, against ``README.md``'s promise.
        invented: Record bytes that no uncited captured byte accounts for —
            a byte both written and cited, or written twice.
        mismatched: Record bytes that differ from the uncited captured byte
            at their offset.
        miscited: Cited bytes outside every captured payload.
        gaps: ``stats.gaps``.
        gaps_in_file: ``Gap`` chunks across both directions.
        holes: Ranges inside each direction's captured extent that no
            captured packet carries: what the network forced.
        judged: Packets cited as discarded, by what packeteer says they were
            and the reason zpfwire gave: ``("copy", "duplicate-discarded")``
            is right, ``("resend", "duplicate-discarded")`` is a resend taken
            for a copy.  ``copy`` is a ``DUP`` of anything, ``resend`` a
            ``RETRANS``, ``original`` a first transmission (``DATA`` or
            ``CORRUPT``) that lost to an earlier or better copy, and
            ``stray`` a forgery.
        end_reason: The session's end reason.
        expected_end: What the ledger says the capture shows: ``rst`` when
            it holds an RST, ``fin`` when it holds a FIN from each side, and
            otherwise ``capture-end`` — packeteer never resends a lost FIN,
            so a capture missing one never sees the conversation close.

    """

    quiet: int
    invented: int
    mismatched: int
    miscited: int
    gaps: int
    gaps_in_file: int
    holes: int
    judged: dict[tuple[str, str], int]
    end_reason: str | None
    expected_end: str

    @property
    def copies_as_resends(self) -> int:
        """Copies of one transmission judged a resend."""
        return sum(n for (kind, reason), n in self.judged.items()
                   if kind == "copy" and reason != REASON_DUPLICATE)

    @property
    def resends_as_copies(self) -> int:
        """Transmissions of their own — a resend or an original — judged a copy."""
        return sum(self.judged.get((kind, REASON_DUPLICATE), 0) for kind in ("resend", "original"))

    def failures(self, *, late_bytes: int = 0) -> list[str]:
        """Return each way the file or its stats misstate what happened.

        Args:
            late_bytes: ``stats.late_bytes``.  A gap the policy committed and
                the network later filled is a gap with no hole behind it.

        Returns:
            One line per failure.  The duplicate-or-resend judgement is a
            measurement, not a failure, and is not among them.

        """
        failures = []
        if self.quiet:
            failures.append(f"{self.quiet} captured bytes reached no record and no citation")
        if self.invented:
            failures.append(f"{self.invented} record bytes come from no uncited captured byte")
        if self.mismatched:
            failures.append(f"{self.mismatched} record bytes differ from the captured byte")
        if self.miscited:
            failures.append(f"{self.miscited} cited bytes lie in no captured payload")
        if self.gaps != self.gaps_in_file:
            failures.append(f"stats.gaps is {self.gaps}, the file has {self.gaps_in_file}")
        if self.gaps_in_file < self.holes or (self.gaps_in_file > self.holes and not late_bytes):
            failures.append(f"the file has {self.gaps_in_file} gaps for {self.holes} holes")
        if self.end_reason != self.expected_end:
            failures.append(f"the session ends {self.end_reason!r}, not {self.expected_end!r}")
        return failures


def account(run: Run, conversion: Conversion) -> Accounting:
    """Check a conversion's file and stats against the ledger.

    Args:
        run: The run converted.  Its stream must be the one converted, since
            citations are located in that stream's capture.
        conversion: The conversion.

    Returns:
        The accounting.

    """
    output = conversion.output
    payloads = _payload_locations(run)
    starts = [start for start, _, _ in payloads]
    cited: dict[int, list[tuple[int, int]]] = {}
    reasons: dict[int, set[str]] = {}
    miscited = 0
    for start, stop, reason in output.undecoded:
        at = bisect.bisect_right(starts, start) - 1
        if at < 0 or stop > payloads[at][1]:
            miscited += stop - start
            continue
        base, _, entry = payloads[at]
        cited.setdefault(entry.index, []).append((start - base, stop - base))
        reasons.setdefault(entry.index, set()).add(reason)

    quiet = invented = mismatched = 0
    for direction in DIRECTIONS:
        pieces = [
            (entry.offset + a, entry.payload[a:b])
            for entry in run.ledger.data(direction)
            for a, b in _complement(cited.get(entry.index, []), entry.length)
        ]
        written = [(offset, record.payload) for offset, record in output.records[direction]]
        q, i = _multiplicity(pieces, written)
        quiet += q
        invented += i
        mismatched += _mismatched(pieces, written)

    judged: dict[tuple[str, str], int] = {}
    for index, why in reasons.items():
        entry = run.ledger.entries[index]
        kind = (
            "stray" if entry.stray
            else "copy" if entry.kind == "DUP"
            else "resend" if entry.kind == "RETRANS"
            else "original"
        )
        for reason in why:
            judged[kind, reason] = judged.get((kind, reason), 0) + 1

    return Accounting(
        quiet=quiet,
        invented=invented,
        mismatched=mismatched,
        miscited=miscited,
        gaps=conversion.stats.gaps,
        gaps_in_file=sum(isinstance(c, zpf.Gap) for d in DIRECTIONS for c in output.chunks[d]),
        holes=sum(_holes(run.ledger, d) for d in DIRECTIONS),
        judged=judged,
        end_reason=output.end_reason,
        expected_end=_expected_end(run.ledger),
    )


def _expected_end(ledger: Ledger) -> str:
    """Return how the captured conversation ends, by the ledger."""
    if ledger.reset:
        return "rst"
    closed = {e.direction for e in ledger.entries if e.flags & TCP_FIN}
    return "fin" if closed == set(DIRECTIONS) else "capture-end"


def _payload_locations(run: Run) -> list[tuple[int, int, Entry]]:
    """Each payload's ``(start, end, entry)`` in the capture's bytes, in order."""
    locations = []
    at = _PCAP_HEADER
    for packet, entry in zip(run.stream.packets, run.ledger.entries, strict=True):
        frame = at + _PCAP_RECORD
        if entry.length:
            start = frame + entry.payload_at
            locations.append((start, start + entry.length, entry))
        at = frame + len(packet.raw)
    return locations


def _complement(ranges: list[tuple[int, int]], length: int) -> list[tuple[int, int]]:
    """Return the parts of ``[0, length)`` that *ranges* do not cover."""
    out = []
    edge = 0
    for start, stop in sorted(ranges):
        if start > edge:
            out.append((edge, start))
        edge = max(edge, stop)
    if edge < length:
        out.append((edge, length))
    return out


def _multiplicity(
    pieces: list[tuple[int, bytes]], written: list[tuple[int, bytes]],
) -> tuple[int, int]:
    """Compare how many uncited bytes and record bytes fall at each offset.

    Returns:
        Bytes uncited more often than written, and written more often than
        uncited.

    """
    events: dict[int, list[int]] = {}
    for column, spans in ((0, pieces), (1, written)):
        for offset, data in spans:
            events.setdefault(offset, [0, 0])[column] += 1
            events.setdefault(offset + len(data), [0, 0])[column] -= 1
    quiet = invented = 0
    depth = [0, 0]
    previous = 0
    for position in sorted(events):
        width = position - previous
        if depth[0] > depth[1]:
            quiet += (depth[0] - depth[1]) * width
        elif depth[1] > depth[0]:
            invented += (depth[1] - depth[0]) * width
        depth = [depth[0] + events[position][0], depth[1] + events[position][1]]
        previous = position
    return quiet, invented


def _mismatched(pieces: list[tuple[int, bytes]], written: list[tuple[int, bytes]]) -> int:
    """Count record bytes that differ from an uncited captured byte at their offset."""
    if not written:
        return 0
    extent = max(offset + len(data) for offset, data in written)
    image = bytearray(extent)
    for offset, data in written:
        image[offset:offset + len(data)] = data
    differing = 0
    for offset, data in pieces:
        stop = min(offset + len(data), extent)
        if offset >= stop:
            continue
        mine = data[:stop - offset]
        if image[offset:stop] != mine:
            differing += sum(a != b for a, b in zip(image[offset:stop], mine, strict=True))
    return differing


def _holes(ledger: Ledger, direction: Direction) -> int:
    """Count the ranges below a direction's furthest captured byte that nothing carries."""
    spans = sorted((e.offset, e.end) for e in ledger.data(direction))
    holes = 0
    edge = 0
    for start, stop in spans:
        if start > edge:
            holes += 1
        edge = max(edge, stop)
    return holes


# ── Order and timing ────────────────────────────────────────────────────


@dataclass(frozen=True)
class Timing:
    """When the file says a message was sent, against when it was.

    Read from the record holding the message's first byte.  A coalesced
    record is one unit, so its ``timestamp`` is when its *last* packet
    arrived and its ``ts_first`` when its first did: a message that does
    not start its record, or does not end it, is dated by its neighbours.

    Attributes:
        message: The message's index.
        recovered: Whether its first segment's original was lost and only a
            resend captured.  The true send time is then the resend's less
            the retransmission timeout — what packeteer schedules it at —
            and the record is expected to be late by about that much.
        correct: Whether the file holds the true byte there.  A forged first
            byte is timed too, and what it times is the forgery.
        starts_record: Whether the message's first byte is its record's.
        timestamp_error: The record's ``timestamp`` less the true send time,
            in microseconds.
        ts_first_error: The same for ``ts_first``, or ``None`` where the
            record carries none.

    """

    message: int
    recovered: bool
    correct: bool
    starts_record: bool
    timestamp_error: int
    ts_first_error: int | None


@dataclass(frozen=True)
class OrderScore:
    """Where each message's first byte falls in the session's timeline.

    packeteer emits messages strictly in order, but message order is not the
    causal order once a segment is lost: the generator keeps sending, and a
    receiver's acknowledgement stays at the hole, so a reply sent meanwhile
    acknowledges nothing of the message it follows.  What the wire
    establishes is narrower, and it is what neither the causal merge nor a
    sequenced session may break: message *j* **depends on** message *i*
    when *j*'s first segment, as first captured, acknowledged *i*'s first
    byte, or *i* is earlier in *j*'s own direction — closed transitively.

    Attributes:
        positions: Each message's first byte's position in the timeline,
            counting records with payload; ``None`` where the file does not
            hold that byte.
        inversions: Pairs where a message is placed before one it depends
            on: each a failure.  Pairs involving a forged first byte are not
            counted — the forgery's position is the forgery's.
        reordered: Pairs placed against plain message order, dependency or
            not.  Reported, not a failure.  Two messages whose first bytes
            share a record are not a pair: the record's offsets order them.
        forged: Messages whose first byte the file holds wrongly.
        timing: One sample per placed message.

    """

    positions: tuple[int | None, ...]
    inversions: int
    reordered: int
    forged: int
    timing: tuple[Timing, ...]

    @property
    def unplaced(self) -> int:
        """Messages whose first byte the file does not hold."""
        return sum(p is None for p in self.positions)


def dependencies(run: Run) -> list[set[int]]:
    """Return, for each message, the earlier messages it depends on.

    Args:
        run: The run.

    Returns:
        ``deps[j]``: the messages *j* depends on, transitively.  See
        :class:`OrderScore`.

    """
    messages = run.truth.messages
    deps: list[set[int]] = []
    for j, message in enumerate(messages):
        first = _first_copy(run.ledger, message.direction, message.offset)
        direct = {
            i for i, earlier in enumerate(messages[:j])
            if earlier.direction == message.direction
            or (first is not None and first.acked is not None and first.acked > earlier.offset)
        }
        closed = set(direct)
        for i in direct:
            closed |= deps[i]
        deps.append(closed)
    return deps


def _first_copy(ledger: Ledger, direction: Direction, offset: int) -> Entry | None:
    """Return the earliest captured, non-stray packet carrying *offset*."""
    carriers = [e for e in ledger.data(direction)
                if not e.stray and e.offset <= offset < e.end]
    return min(carriers, key=lambda e: e.usec, default=None)


def score_order(run: Run, output: Output) -> OrderScore:
    """Score the order and timing of a converted run's messages.

    Args:
        run: The run.
        output: What its conversion holds.

    Returns:
        The score.

    """
    placed: dict[Direction, list[tuple[int, int, int]]] = {d: [] for d in DIRECTIONS}
    for position, (direction, offset, record) in enumerate(output.timeline):
        placed[direction].append((offset, offset + len(record.payload), position))
    for spans in placed.values():
        spans.sort()

    positions: list[int | None] = []
    timing = []
    rto = round(run.scenario.impairments.retransmission_timeout * 1_000_000)
    for message in run.truth.messages:
        spans = placed[message.direction]
        at = bisect.bisect_right(spans, (message.offset, _WRAP, 0)) - 1
        if at < 0 or not spans[at][0] <= message.offset < spans[at][1]:
            positions.append(None)
            continue
        start, _, position = spans[at]
        positions.append(position)
        segment = next(
            (s for s in run.ledger.segments if s.direction == message.direction
             and s.offset <= message.offset < s.offset + s.length),
            None,
        )
        if segment is None:  # a forged byte where nothing real was captured
            continue
        sent = segment.first_usec - rto if segment.sent_usec is None else segment.sent_usec
        record = output.timeline[position][2]
        held = record.payload[message.offset - start]
        timing.append(Timing(
            message=message.index,
            recovered=segment.sent_usec is None,
            correct=held == run.truth.streams[message.direction][message.offset],
            starts_record=start == message.offset,
            timestamp_error=output.usec(record.timestamp) - sent,
            ts_first_error=None if record.ts_first is None else output.usec(record.ts_first) - sent,
        ))

    forged = {t.message for t in timing if not t.correct}
    deps = dependencies(run)

    def placed_after(i: int, j: int) -> bool:
        a, b = positions[i], positions[j]
        return a is not None and b is not None and a > b

    pairs = [(i, j) for j in range(len(positions)) for i in range(j)]
    return OrderScore(
        positions=tuple(positions),
        inversions=sum(
            1 for i, j in pairs
            if i in deps[j] and i not in forged and j not in forged and placed_after(i, j)
        ),
        reordered=sum(1 for i, j in pairs if placed_after(i, j)),
        forged=len(forged),
        timing=tuple(timing),
    )


# ── A measurement ───────────────────────────────────────────────────────


@dataclass(frozen=True)
class Measurement:
    """One run, converted under one policy, scored and accounted for.

    Attributes:
        run: The run.
        conversion: Its conversion.
        bytes: The byte score, by direction.
        accounting: The file's account of itself.
        order: The messages' order and timing.

    """

    run: Run
    conversion: Conversion
    bytes: dict[Direction, ByteScore]
    accounting: Accounting
    order: OrderScore

    @property
    def total(self) -> ByteScore:
        """Both directions' scores, added."""
        return self.bytes["c2s"] + self.bytes["s2c"]


def measure(
    run: Run, options: ReassemblyOptions | None = None, *, sequenced: bool = False,
) -> Measurement:
    """Convert a run, read it back, and score it.

    A void run is measured all the same: :attr:`Run.void` is what keeps it
    out of a report, and a test may want its numbers regardless.

    Args:
        run: The run.
        options: The reassembly policy; zpfwire's defaults when ``None``.
        sequenced: Whether to write the session in causal order.

    Returns:
        The measurement.

    Raises:
        Unclean: If the file does not read back clean.

    """
    conversion = convert(run.stream, options, sequenced=sequenced)
    return Measurement(
        run=run,
        conversion=conversion,
        bytes={d: score_bytes(run, conversion.output, d) for d in DIRECTIONS},
        accounting=account(run, conversion),
        order=score_order(run, conversion.output),
    )
