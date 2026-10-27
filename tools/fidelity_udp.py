"""Measure how well a UDP conversion represents the datagrams that were actually sent.

The UDP half of the fidelity tool (``tools/fidelity.py``), from ``0.8.0``
(#64).  ``plans/V0.8.0-RELEASE-PLAN.md`` is the design.  A UDP stream has no
sequence numbers, so nothing is placed by offset: what can go wrong is which
datagrams arrived, how many times, and in what order.

**The truth and the ledger** (Phase 3) are built from the generator alone.
They never consult zpfwire: they are the reference the conversion is
measured against, so they must not be derived from the thing measured.

- :class:`Scenario` — datagrams by direction and size, a seed, an MTU, and
  :class:`Impairments`.
- :class:`Truth` — each datagram the applications sent, with its true send
  time.  Payloads are position-unique, so a record can be traced to its
  datagram by its bytes.
- :class:`Ledger` — one :class:`Copy` per datagram the capture holds,
  reassembled from its fragments, and the datagrams it does not hold.
- :func:`self_check` — the conditions under which the run is not evidence
  about zpfwire at all, and is voided rather than scored.

**The scorer** (Phase 4) converts the run along either path — a pcap, or a
``.zpf`` of its packets as a tunnel decryptor writes one — and reads the
file back through zpf's public reader only.

- :func:`measure` — convert, read back, score.  A file that fails this
  project's load-bearing assertion raises :class:`Unclean`.
- :func:`match` — each record paired with the captured copy it carries, by
  its bytes, in order.
- :class:`Delivery` — what became of each datagram sent (delivered,
  lost, withheld, repeated, altered) and of each copy captured.
- :class:`Accounting` — whether the file and its stats tell the truth about
  themselves: every copy in one record or wholly cited, capture order, the
  capture time, provenance, the stats.
- :class:`OrderScore` — inversions of send order, each explained by a
  datagram the ledger shows held back, and timing.
"""

from __future__ import annotations

import bisect
import dataclasses
import io
import ipaddress
import re
import struct
from dataclasses import dataclass
from typing import Literal

import zpf
from fidelity_common import (
    BASE_TIME,
    CLIENT,
    DIRECTIONS,
    PCAP_HEADER,
    PCAP_RECORD,
    Direction,
    Unclean,
    kinds_of,
    payload,
)
from packeteer.generate.impairments import ImpairmentConfig
from packeteer.generate.payloads.base import AppMessage
from packeteer.generate.udp_stream import (
    UDPStream,
    UDPStreamConfig,
    UDPStreamPacket,
    generate_udp_stream,
)
from packeteer.parse import parse_packet
from packeteer.pcap import LINKTYPE_ETHERNET, write_pcap

from zpfwire import ConversionStats, ReassemblyOptions, capture_to_zpf, packets_to_zpf

SERVER = ("10.0.0.2", 5000)
"""The server's address and port: a participant there sends ``s2c``."""

GAP_USEC = 1000
"""packeteer's default gap between datagrams, in microseconds.  With no
jitter, datagram *i* is sent at ``BASE_TIME`` plus ``(i + 1) * GAP_USEC``."""

_UDP_HEADER = 8
_FRAG = re.compile(r"FRAG\[(.*)\]\[(\d+)\]$")
_INDEX = re.compile(r"\[(\d+)\]")

PROTOTYPE: tuple[tuple[Direction, int], ...] = tuple(
    ("c2s" if i % 2 == 0 else "s2c", 100 + (i * 337) % 1300) for i in range(40)
)
"""The ``0.8.0`` prototype's 40 datagrams: alternating ways, 100–1,399 bytes."""


# ── The scenario ────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Impairments:
    """What the network does to a UDP flow, as packeteer configures it.

    Each field is the :class:`~packeteer.generate.impairments.ImpairmentConfig`
    field of the same name, and means what it means there.  These are the
    fields packeteer reads for a datagram flow; the rest describe a
    connection.  What was configured, not what happened: that is the
    :class:`Ledger`'s to say.

    Attributes:
        packet_loss_probability: Chance a datagram is lost.
        payload_corruption_probability: Chance a datagram's last byte is
            flipped in flight.  Nothing resends it.
        reorder_probability: Chance a datagram is held back behind later
            ones going its way.
        reorder_depth: The most datagrams a held one waits behind.
        duplicate_probability: Chance the capture point sees a datagram twice.

    """

    packet_loss_probability: float = 0.0
    payload_corruption_probability: float = 0.0
    reorder_probability: float = 0.0
    reorder_depth: int = 3
    duplicate_probability: float = 0.0


@dataclass(frozen=True)
class Scenario:
    """One generated flow: what is sent, the seed, the path, and the impairments.

    Attributes:
        shape: Each datagram's direction and length, in the order sent.
        seed: packeteer's seed.  Payloads do not depend on it.
        impairments: What the network does to it.
        mtu: When set, a middlebox fragments each IP datagram larger than
            this, after the impairments, as packeteer orders them.

    """

    shape: tuple[tuple[Direction, int], ...] = PROTOTYPE
    seed: int = 0
    impairments: Impairments = Impairments()
    mtu: int | None = None

    def messages(self) -> list[AppMessage]:
        """Return the datagrams, each payload position-unique.

        Returns:
            One :class:`~packeteer.generate.payloads.base.AppMessage` per
            entry of :attr:`shape`.

        """
        return [
            AppMessage(direction, payload(direction, index, length), f"d{index}")
            for index, (direction, length) in enumerate(self.shape)
        ]

    def generate(self) -> UDPStream:
        """Generate the impaired flow.

        Returns:
            packeteer's stream, deterministic in the scenario.

        """
        messages = self.messages()
        return generate_udp_stream(
            client_ip=CLIENT[0], client_port=CLIENT[1],
            server_ip=SERVER[0], server_port=SERVER[1],
            # packeteer sends ``messages[i % len(messages)]`` for each of
            # ``num_data_packets``, so anything else would repeat or truncate.
            num_data_packets=len(messages),
            inter_packet_gap=GAP_USEC / 1_000_000,
            mtu=self.mtu,
            config=UDPStreamConfig(
                seed=self.seed, base_time=BASE_TIME, messages=messages,
                impairments=ImpairmentConfig(**dataclasses.asdict(self.impairments)),
            ),
        )


# ── The truth ───────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Datagram:
    """One datagram an application sent.

    Attributes:
        index: Its position in the scenario, which is send order.
        direction: Which way it travels.
        data: Its payload.
        sent_usec: When it was sent, in microseconds since the epoch.

    """

    index: int
    direction: Direction
    data: bytes
    sent_usec: int


@dataclass(frozen=True)
class Truth:
    """What each application sent: its datagrams, in send order.

    Independent of every impairment by construction.  packeteer draws each
    datagram's time before any impairment, and a lost datagram was still
    sent.

    Attributes:
        datagrams: Every datagram, in the order sent.

    """

    datagrams: tuple[Datagram, ...]

    @classmethod
    def of(cls, scenario: Scenario) -> Truth:
        """Build the truth for a scenario.

        Args:
            scenario: The scenario.

        Returns:
            Its truth.

        """
        start = BASE_TIME * 1_000_000
        return cls(tuple(
            Datagram(index, message.direction, message.data, start + (index + 1) * GAP_USEC)
            for index, message in enumerate(scenario.messages())
        ))


# ── The ledger ──────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Piece:
    """Where some of a copy's payload sits in one captured frame.

    Attributes:
        packet: The frame's position in ``stream.packets``.
        at: Where the bytes start in the frame.
        offset: Where they start in the datagram's payload.
        length: How many.

    """

    packet: int
    at: int
    offset: int
    length: int


@dataclass(frozen=True)
class Copy:
    """One datagram as the capture holds it, reassembled from its fragments.

    Attributes:
        datagram: The truth's index of the datagram it carries.
        label: packeteer's label, without the ``FRAG[…][i]`` around a
            fragment: e.g. ``DATA[3]``, ``DUP[CORRUPT[3]]``.
        kinds: The label's kinds, outermost first: ``("DUP", "CORRUPT")``.
            packeteer drops ``DATA`` from a label it derives, so
            ``REORDER[3]`` holds a data datagram, and its kinds are
            ``("REORDER",)``.
        direction: Which way it travels.
        packets: The frames it was captured as, in ``stream.packets``
            positions: one, or one per fragment.
        first_usec: When its first frame was captured, in microseconds
            since the epoch.  packeteer stamps each later fragment at the
            next microsecond no other frame holds.
        usec: When the capture point had all of it: the last frame's
            capture time.
        payload: Its payload, as captured.
        checksum_ok: Whether its UDP checksum verifies.  A zero checksum is
            "none", which verifies anything.
        pieces: Where its payload sits in the captured frames.

    """

    datagram: int
    label: str
    kinds: tuple[str, ...]
    direction: Direction
    packets: tuple[int, ...]
    first_usec: int
    usec: int
    payload: bytes
    checksum_ok: bool
    pieces: tuple[Piece, ...]

    @property
    def kind(self) -> str:
        """The outermost kind: what this copy is."""
        return self.kinds[0]

    @property
    def corrupt(self) -> bool:
        """Whether its payload was corrupted in flight, as itself or as a copy of one."""
        return "CORRUPT" in self.kinds

    @property
    def fragmented(self) -> bool:
        """Whether it was captured as fragments."""
        return len(self.packets) > 1


@dataclass(frozen=True)
class Ledger:
    """What happened to every datagram the scenario sent.

    Attributes:
        copies: One per datagram copy the capture holds, in the order the
            capture point completed them.
        lost: The datagrams no copy carries: lost on the wire.
        overtaken: For each copy, how many datagrams going its way, sent
            after it, the capture point had completed first.  Nonzero for a
            reordered datagram, and what explains an inversion.

    """

    copies: tuple[Copy, ...]
    lost: tuple[int, ...]
    overtaken: tuple[int, ...]

    @classmethod
    def of(cls, stream: UDPStream, truth: Truth) -> Ledger:
        """Build the ledger of a generated flow against its truth.

        Args:
            stream: packeteer's stream.
            truth: The scenario's truth.

        Returns:
            Its ledger.

        """
        groups: dict[str, list[tuple[int, int, UDPStreamPacket]]] = {}
        for index, packet in enumerate(stream.packets):
            match = _FRAG.match(packet.label)
            label, fragment = (match.group(1), int(match.group(2))) if match else (packet.label, 0)
            # A copy's frames share its label; two copies of a datagram
            # differ in theirs, ``DUP[…]`` around the second.
            groups.setdefault(label, []).append((fragment, index, packet))
        copies = sorted(
            (_copy(label, frames) for label, frames in groups.items()),
            key=lambda c: c.packets[-1],
        )
        carried = {c.datagram for c in copies}
        overtaken = []
        for i, copy in enumerate(copies):
            earlier = {c.datagram for c in copies[:i] if c.direction == copy.direction}
            overtaken.append(sum(1 for d in earlier if d > copy.datagram))
        return cls(
            copies=tuple(copies),
            lost=tuple(d.index for d in truth.datagrams if d.index not in carried),
            overtaken=tuple(overtaken),
        )

    def kinds(self) -> dict[str, int]:
        """Count the copies by outermost kind: what the run realised.

        Returns:
            ``{kind: count}``.  A lost datagram is not a copy; see
            :attr:`lost`.

        """
        counts: dict[str, int] = {}
        for copy in self.copies:
            counts[copy.kind] = counts.get(copy.kind, 0) + 1
        return counts

    def of_datagram(self, index: int) -> tuple[Copy, ...]:
        """Return every copy of one datagram, in capture order.

        Args:
            index: The datagram's index in the truth.

        Returns:
            Its copies; none if it was lost.

        """
        return tuple(c for c in self.copies if c.datagram == index)


def _direction(packet: UDPStreamPacket) -> Direction:
    assert packet.direction in DIRECTIONS, packet.direction
    return packet.direction


def _copy(label: str, frames: list[tuple[int, int, UDPStreamPacket]]) -> Copy:
    """Reassemble one copy from its frames, in fragment order.

    The UDP header travels in the first fragment only, so the checksum is
    computed here over the whole datagram, with the IPv4 pseudo-header; a
    parser handed a fragment cannot verify it.
    """
    frames = sorted(frames, key=lambda f: f[0])
    assert [f[0] for f in frames] == list(range(len(frames))), (label, [f[0] for f in frames])
    body = bytearray()
    pieces: list[Piece] = []
    src = dst = ""
    for fragment, index, packet in frames:
        parsed = parse_packet(packet.raw, decode_app=False)
        assert parsed.ip is not None, f"packet {index} ({packet.label}) has no IP header"
        ip_at = parsed.offsets["ip"]
        start = parsed.offsets["transport"] if fragment == 0 else parsed.payload_offset
        assert start is not None, f"packet {index} ({packet.label}) has no IP payload"
        length = parsed.ip.total_length - (start - ip_at)
        assert len(body) == parsed.ip.fragment_offset * 8, (label, fragment)
        more = bool(parsed.ip.flags & 1)
        assert more == (fragment < len(frames) - 1), f"{label}: {fragment} of {len(frames)}"
        chunk = packet.raw[start:start + length]
        # The first fragment's payload begins with the UDP header.
        data_at = start + (_UDP_HEADER if fragment == 0 else 0)
        data_offset = len(body) + (_UDP_HEADER if fragment == 0 else 0) - _UDP_HEADER
        if start + length > data_at:
            pieces.append(Piece(index, data_at, data_offset, start + length - data_at))
        body += chunk
        src, dst = parsed.ip.src, parsed.ip.dst
    first, last = frames[0][2], frames[-1][2]
    number = _INDEX.search(label)
    assert number is not None, f"{label} names no datagram"
    return Copy(
        datagram=int(number.group(1)),
        label=label,
        kinds=kinds_of(label),
        direction=_direction(last),
        packets=tuple(index for _, index, _ in frames),
        first_usec=first.ts_sec * 1_000_000 + first.ts_usec,
        usec=last.ts_sec * 1_000_000 + last.ts_usec,
        payload=bytes(body[_UDP_HEADER:]),
        checksum_ok=_checksum_ok(src, dst, bytes(body)),
        pieces=tuple(pieces),
    )


def _checksum_ok(src: str, dst: str, datagram: bytes) -> bool:
    """Return whether a UDP datagram's checksum verifies over the IPv4 pseudo-header."""
    if datagram[6:8] == b"\x00\x00":
        return True
    pseudo = (ipaddress.IPv4Address(src).packed + ipaddress.IPv4Address(dst).packed
              + struct.pack("!BBH", 0, 17, len(datagram)))
    data = pseudo + datagram + (b"\x00" if len(datagram) % 2 else b"")
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total == 0xFFFF


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
    by_label = {c.label: c for c in ledger.copies}
    for copy in ledger.copies:
        sent = truth.datagrams[copy.datagram]
        if copy.direction != sent.direction:
            failures.append(f"{copy.label} travels {copy.direction}, its datagram {sent.direction}")
        # A corrupted datagram has its last IP byte flipped: the payload's
        # last byte, or the checksum's when there is no payload.  Either
        # way its checksum must fail, or nothing could tell it from the
        # real one — packeteer#227's shape, for UDP.
        if copy.corrupt == copy.checksum_ok:
            failures.append(
                f"{copy.label} is {'' if copy.corrupt else 'not '}corrupt, and its checksum "
                f"{'verifies' if copy.checksum_ok else 'fails'}"
            )
        if copy.corrupt:
            same = len(copy.payload) == len(sent.data) and copy.payload[:-1] == sent.data[:-1]
            if not same:
                failures.append(f"{copy.label} differs from its datagram beyond the last byte")
        elif copy.payload != sent.data:
            failures.append(f"{copy.label} does not carry its datagram's bytes")
        if copy.kind == "DATA" and copy.first_usec != sent.sent_usec:
            failures.append(
                f"{copy.label} was first captured at {copy.first_usec}, "
                f"not its send time {sent.sent_usec}"
            )
        # A capture-point copy is the same transmission: the same datagram,
        # bytes and checksum, at another capture time.
        if copy.kind == "DUP":
            inner = copy.label[len("DUP["):-1]
            # packeteer drops DATA when it derives a label: DUP[4] copies DATA[4].
            original = by_label.get(f"DATA[{inner}]" if inner.isdigit() else inner)
            if original is None:
                failures.append(f"{copy.label} copies nothing the capture holds")
            elif (original.payload, original.checksum_ok) != (copy.payload, copy.checksum_ok):
                failures.append(f"{copy.label} differs from {original.label}")
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
    stream: UDPStream
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


Path = Literal["capture", "packets"]
"""How a run reaches zpfwire: as a pcap, or as a ``.zpf`` of its packets."""

PATHS: tuple[Path, Path] = ("capture", "packets")

_ETHERNET = 14
"""Bytes before every frame's IP header: the generator adds Ethernet and no encapsulation."""


@dataclass(frozen=True)
class Written:
    """One record, as a reader of the converted file gets it.

    Attributes:
        payload: Its bytes.
        usec: Its ``timestamp``, in microseconds since the epoch.
        flags: Its record flags.
        spans: Its provenance, as ``(participant, start, end)`` in the input
            ``.zpf``'s offset space; empty for a capture-sourced record.

    """

    payload: bytes
    usec: int
    flags: zpf.RecordFlags
    spans: tuple[tuple[int, int, int], ...]


@dataclass(frozen=True)
class Output:
    """What a reader of the converted file gets.

    Attributes:
        records: Each direction's records, in stored order.
        timeline: Every record, as ``(direction, record)``, in
            :meth:`zpf.SessionReader.timeline` order, session by session.
        undecoded: Every Undecoded block, as ``(participant, start, end,
            reason)``: ``participant`` is the input ``.zpf``'s, or ``None``
            where the block cites capture-file bytes.
        end_reasons: Each session's end reason.

    """

    records: dict[Direction, tuple[Written, ...]]
    timeline: tuple[tuple[Direction, Written], ...]
    undecoded: tuple[tuple[int | None, int, int, str], ...]
    end_reasons: tuple[str | None, ...]


@dataclass(frozen=True)
class Conversion:
    """One run converted along one path, under one policy.

    Attributes:
        path: How the run reached zpfwire.
        options: The reassembly policy.
        sequenced: Whether causal order was asked for, which zpfwire
            applies to TCP sessions only.
        stats: What the conversion reported.
        output: What the file holds.
        frames: Where each frame of ``stream.packets`` sits in the space a
            citation names: ``(None, start)`` in the capture file, or
            ``(participant, start)`` in the input ``.zpf``, where the
            record is the frame from its IP header on.
        data: The file itself.

    """

    path: Path
    options: ReassemblyOptions
    sequenced: bool
    stats: ConversionStats
    output: Output
    frames: tuple[tuple[int | None, int], ...]
    data: bytes = dataclasses.field(default=b"", repr=False)

    def locate(self, frame: int, at: int) -> tuple[int | None, int]:
        """Return where byte *at* of a frame sits in the space a citation names.

        Args:
            frame: The frame's position in ``stream.packets``.
            at: A byte offset in the frame.

        Returns:
            ``(participant, offset)``; the participant is ``None`` in the
            capture file.

        """
        space, start = self.frames[frame]
        return space, start + (at if space is None else at - _ETHERNET)


def packets_of(stream: UDPStream) -> tuple[bytes, tuple[tuple[int | None, int], ...]]:
    """Write a stream's frames as a ``.zpf`` of packets: what a tunnel decryptor writes.

    One session, one participant per direction, each frame a ``net:ip``
    record from its IP header on, padding included, in capture order.  A
    capture-sourced decoded file, as ``tests/helpers.py``'s ``packets_zpf``
    writes by default, built from the stream so that where each frame lands
    is known.

    Args:
        stream: packeteer's stream.

    Returns:
        The file, and each frame's ``(participant, start)`` in its
        participant's offset space.

    """
    sink = io.BytesIO()
    frames: list[tuple[int | None, int]] = []
    with zpf.create(sink, tick_hz=1_000_000, produced_by="zpfwire fidelity",
                    produced_at=BASE_TIME) as writer:
        writer.add_source("capture", link_type=LINKTYPE_ETHERNET)
        decoder = writer.add_decoder("tunnel", output_layer=zpf.OutputLayer.DECODED, version="0")
        session = writer.begin_session(proto="ip", key="tunnel")
        handles = {d: session.participant(f"tunnel-{d}", adjacency=zpf.Adjacency.UNITS)
                   for d in DIRECTIONS}
        ends = dict.fromkeys(DIRECTIONS, 0)
        for packet in stream.packets:
            direction = _direction(packet)
            record = packet.raw[_ETHERNET:]
            frames.append((DIRECTIONS.index(direction), ends[direction]))
            ends[direction] += len(record)
            session.record(
                handles[direction], ts=packet.ts_sec * 1_000_000 + packet.ts_usec,
                payload=record,
                decoded=zpf.Decoded(decoder=decoder, content_type=zpf.NET_IP),
            )
        session.end()
    return sink.getvalue(), tuple(frames)


def convert(
    stream: UDPStream,
    options: ReassemblyOptions | None = None,
    *,
    path: Path = "capture",
    sequenced: bool = False,
) -> Conversion:
    """Convert a generated stream in memory, along one path, and read the file back.

    Args:
        stream: The stream, usually a :attr:`Run.stream`.
        options: The reassembly policy; zpfwire's defaults when ``None``.
        path: ``"capture"`` converts a pcap of the stream;
            ``"packets"`` converts a ``.zpf`` of its packets.
        sequenced: Whether to ask for causal order.

    Returns:
        The conversion.

    Raises:
        Unclean: If the file does not read back clean.

    """
    options = options or ReassemblyOptions()
    sink = io.BytesIO()
    if path == "capture":
        capture = io.BytesIO()
        write_pcap(stream.to_pcap_tuples(), file_object=capture)
        capture.seek(0)
        stats = capture_to_zpf(capture, sink, options=options, sequenced=sequenced,
                               produced_at=None)
        frames: list[tuple[int | None, int]] = []
        at = PCAP_HEADER
        for packet in stream.packets:
            frames.append((None, at + PCAP_RECORD))
            at += PCAP_RECORD + len(packet.raw)
        located = tuple(frames)
    else:
        packets, located = packets_of(stream)
        stats = packets_to_zpf(io.BytesIO(packets), sink, options=options,
                               sequenced=sequenced, produced_at=BASE_TIME)
    data = sink.getvalue()
    return Conversion(path, options, sequenced, stats, read(data), located, data)


def read(data: bytes) -> Output:
    """Read a converted file through zpf's public reader.

    Args:
        data: The ``.zpf`` file's bytes.

    Returns:
        What it holds.

    Raises:
        Unclean: If it does not read back clean.

    """
    endpoints = {"{}:{}".format(*CLIENT): "c2s", "{}:{}".format(*SERVER): "s2c"}
    records: dict[Direction, list[Written]] = {d: [] for d in DIRECTIONS}
    timeline: list[tuple[Direction, Written]] = []
    ends: list[str | None] = []
    with zpf.open(io.BytesIO(data)) as reader:
        tick_hz = 0
        epoch = 0
        for session in reader.sessions():
            header = reader.header
            assert header is not None, "a file with a session has a header"
            tick_hz, epoch = header.tick_hz, header.time_epoch or 0
            ends.append(session.end.reason if session.end else None)
            direction_of: dict[int, Direction] = {}
            for participant in session.participants:
                direction: Direction = endpoints[participant.endpoint]  # type: ignore[assignment]
                direction_of[participant.participant_id] = direction
                records[direction] += [
                    _written(r, tick_hz, epoch)
                    for r in session.stream(participant.participant_id)
                ]
            timeline += [
                (direction_of[r.sender_pid], _written(r, tick_hz, epoch))
                for r in session.timeline()
            ]
        if reader.diagnostics or reader.unplaceable:
            raise Unclean(f"diagnostics {reader.diagnostics}, unplaceable {reader.unplaceable}")
        # A capture-sourced file cites capture-file bytes; a derived one cites
        # its input's participants.
        derived = bool(reader.header and reader.header.produced_by)
        undecoded = tuple(
            (u.participant_id if derived else None, u.off_start, u.off_end, u.reason or "")
            for u in reader.undecoded
        )
    return Output({d: tuple(r) for d, r in records.items()}, tuple(timeline), undecoded,
                  tuple(ends))


def _written(record: zpf.Record, tick_hz: int, epoch: int) -> Written:
    return Written(
        payload=bytes(record.payload or b""),
        usec=(epoch + record.timestamp) * 1_000_000 // tick_hz,
        flags=zpf.RecordFlags(record.flags),
        spans=tuple((s.participant_id, s.off_start, s.off_end) for s in record.spans),
    )


# ── The scorer ──────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Delivery:
    """What became of every datagram sent, and of every copy captured.

    Each sent datagram is one of: **delivered** once with its true bytes;
    **lost** on the wire, so no copy was captured; **withheld**, captured
    and in no record; **repeated**, in more than one record, which is what
    a captured copy must become (the specification forbids withholding it);
    or **altered**, in one record but not with its true bytes, as a kept
    corrupt copy is.

    Attributes:
        sent: Datagrams sent.
        delivered: Sent datagrams in exactly one record, with their true bytes.
        lost: Sent datagrams no copy carries.
        withheld: Captured datagrams in no record.
        repeated: Datagrams in more than one record.
        altered: Datagrams in one record, with bytes other than the truth.
        captured: Copies the capture holds.
        written: Copies that reached a record.
        cited: Copies in no record whose payload every byte of is cited.

    """

    sent: int
    delivered: int
    lost: int
    withheld: int
    repeated: int
    altered: int
    captured: int
    written: int
    cited: int

    @property
    def delivery(self) -> float:
        """Delivered ÷ sent: what a reader of the file gets."""
        return self.delivered / self.sent if self.sent else 1.0

    @property
    def conservation(self) -> float:
        """Written ÷ captured: what zpfwire made of what it was given."""
        return self.written / self.captured if self.captured else 1.0


@dataclass(frozen=True)
class Accounting:
    """Whether the file and its stats tell the truth about themselves.

    Every count is a failure when nonzero, except where it says otherwise.

    Attributes:
        quiet: Copies in no record and not wholly cited: lost quietly.
        doubled: Copies both written and cited.
        partial: Copies in no record whose citation covers some bytes only.
        invented: Records repeating a copy more often than it was captured.
        unknown: Records whose bytes match no captured copy.
        stats: Where the conversion's stats disagree with the ledger.
        flags: Records not flagged ``message``, or flagged ``retransmit``,
            which names a sender's resend that no UDP sender makes here.
        misordered: Records stored out of their copies' capture order.
        timeline: Whether :meth:`zpf.SessionReader.timeline` keeps each
            direction's stored order and runs in time order.
        mistimed: Records whose ``timestamp`` is not the capture time of
            their copy's last frame.
        misattributed: Records whose spans do not name exactly their copy's
            frames; on the packets path, where records carry spans.
        sessions: How many sessions the file holds.
        expected_sessions: How many it should: one flow is one session, and
            none when nothing was written, as when the packets path withholds
            every datagram of a flow (zipline#166).
        end_reasons: Each session's end reason; ``capture-end`` expected.

    """

    quiet: int
    doubled: int
    partial: int
    invented: int
    unknown: int
    stats: tuple[str, ...]
    flags: int
    misordered: int
    timeline: bool
    mistimed: int
    misattributed: int
    sessions: int
    expected_sessions: int
    end_reasons: tuple[str | None, ...]

    def failures(self) -> list[str]:
        """Return each way the file or its stats misstate the conversion.

        Returns:
            One line per failure; empty when the file accounts for itself.

        """
        out = []
        for count, what in (
            (self.quiet, "captured copies reached no record and no citation"),
            (self.doubled, "copies were both written and cited"),
            (self.partial, "copies in no record were cited in part"),
            (self.invented, "records repeat a copy beyond the times it was captured"),
            (self.unknown, "records match no captured copy"),
            (self.flags, "records are flagged wrongly for a datagram"),
            (self.misordered, "records are stored out of capture order"),
            (self.mistimed, "records are not stamped with their copy's capture time"),
            (self.misattributed, "records' spans do not name their copy's frames"),
        ):
            if count:
                out.append(f"{count} {what}")
        out += list(self.stats)
        if not self.timeline:
            out.append("the timeline does not follow stored and capture order")
        if self.sessions != self.expected_sessions:
            out.append(f"{self.sessions} sessions, not {self.expected_sessions}")
        if any(reason != "capture-end" for reason in self.end_reasons):
            out.append(f"end reasons {list(self.end_reasons)}, not capture-end")
        return out


@dataclass(frozen=True)
class Timing:
    """One record's timestamp against its datagram's true send time.

    Attributes:
        datagram: The datagram.
        kind: Its copy's outermost kind.
        held: Whether the network held it back: ``REORDER`` among its
            copy's kinds, a duplicate of a reordered datagram included.
        error_usec: ``timestamp`` less the true send time: what reordering
            or fragmentation delayed it by, as the capture point saw.

    """

    datagram: int
    kind: str
    held: bool
    error_usec: int


@dataclass(frozen=True)
class OrderScore:
    """The order datagrams are stored in, against the order they were sent.

    Attributes:
        inversions: Pairs of records, one direction's, stored in the
            opposite order to their datagrams' sending.  The network's: a
            stream without sequence numbers is stored in arrival order.
        unexplained: Inversions whose later-stored copy the ledger does
            not show reordered.  Each is a failure of the run's evidence.
        timing: One sample per record matched to a copy.

    """

    inversions: int
    unexplained: int
    timing: tuple[Timing, ...]


@dataclass(frozen=True)
class Measurement:
    """One run, converted along one path under one policy, and scored.

    Attributes:
        run: The run.
        conversion: Its conversion.
        delivery: What became of each datagram.
        accounting: The file's account of itself.
        order: The order and timing of what was written.

    """

    run: Run
    conversion: Conversion
    delivery: Delivery
    accounting: Accounting
    order: OrderScore


def match(ledger: Ledger, output: Output) -> dict[Direction, list[Copy | None]]:
    """Pair each record with the captured copy it carries.

    Per direction, records in stored order take the earliest unclaimed copy,
    in capture order, with exactly their bytes.  Two copies of one datagram
    are the same bytes, so which record takes which is decided by order,
    which is also what the order checks then judge.

    Args:
        ledger: The run's ledger.
        output: The converted file.

    Returns:
        Each direction's copy for each of its records, ``None`` where the
        bytes match no unclaimed copy.

    """
    out: dict[Direction, list[Copy | None]] = {}
    for direction in DIRECTIONS:
        free = [c for c in ledger.copies if c.direction == direction]
        paired: list[Copy | None] = []
        for record in output.records[direction]:
            copy = next((c for c in free if c.payload == record.payload), None)
            if copy is not None:
                free.remove(copy)
            paired.append(copy)
        out[direction] = paired
    return out


def score(run: Run, conversion: Conversion) -> tuple[Delivery, Accounting, OrderScore]:
    """Score a conversion against its run.

    Args:
        run: The run converted.
        conversion: Its conversion.

    Returns:
        The delivery, the accounting and the order.

    """
    ledger, output = run.ledger, conversion.output
    paired = match(ledger, output)
    written = {id(c) for d in DIRECTIONS for c in paired[d] if c is not None}
    cited = _cited(conversion, run)
    position = {id(c): i for i, c in enumerate(ledger.copies)}

    records_of: dict[int, list[bytes]] = {}
    for direction in DIRECTIONS:
        for record, copy in zip(output.records[direction], paired[direction], strict=True):
            if copy is not None:
                records_of.setdefault(copy.datagram, []).append(record.payload)
    captured = {c.datagram for c in ledger.copies}
    delivered = repeated = altered = 0
    for datagram in run.truth.datagrams:
        held = records_of.get(datagram.index, [])
        if len(held) > 1:
            repeated += 1
        elif held and held[0] == datagram.data:
            delivered += 1
        elif held:
            altered += 1
    delivery = Delivery(
        sent=len(run.truth.datagrams),
        delivered=delivered,
        lost=len(ledger.lost),
        withheld=len(captured - set(records_of)),
        repeated=repeated,
        altered=altered,
        captured=len(ledger.copies),
        written=len(written),
        cited=sum(1 for c in ledger.copies if id(c) not in written and cited[id(c)] == "all"),
    )

    unmatched = [r for d in DIRECTIONS
                 for r, c in zip(output.records[d], paired[d], strict=True) if c is None]
    payloads = {c.payload for c in ledger.copies}
    accounting = Accounting(
        quiet=sum(1 for c in ledger.copies if id(c) not in written and cited[id(c)] == "none"),
        doubled=sum(1 for c in ledger.copies if id(c) in written and cited[id(c)] != "none"),
        partial=sum(1 for c in ledger.copies if id(c) not in written and cited[id(c)] == "some"),
        invented=sum(1 for r in unmatched if r.payload in payloads),
        unknown=sum(1 for r in unmatched if r.payload not in payloads),
        stats=_stats(conversion, output, ledger),
        flags=sum(
            1 for d in DIRECTIONS for r in output.records[d]
            if not r.flags & zpf.RecordFlags.MESSAGE or r.flags & zpf.RecordFlags.RETRANSMIT
        ),
        misordered=sum(sum(_overtakers([position[id(c)] for c in paired[d] if c is not None]))
                       for d in DIRECTIONS),
        timeline=_timeline_ok(output),
        mistimed=sum(
            1 for d in DIRECTIONS
            for r, c in zip(output.records[d], paired[d], strict=True)
            if c is not None and r.usec != c.usec
        ),
        misattributed=sum(
            1 for d in DIRECTIONS
            for r, c in zip(output.records[d], paired[d], strict=True)
            if c is not None and conversion.path == "packets"
            and set(r.spans) != _spans(conversion, run, c)
        ),
        sessions=len(output.end_reasons),
        expected_sessions=1 if any(output.records[d] for d in DIRECTIONS) else 0,
        end_reasons=output.end_reasons,
    )

    inversions = unexplained = 0
    timing = []
    for direction in DIRECTIONS:
        copies = [c for c in paired[direction] if c is not None]
        for copy, overtakers in zip(copies, _overtakers([c.datagram for c in copies]),
                                    strict=True):
            inversions += overtakers
            if "REORDER" not in copy.kinds:
                unexplained += overtakers
        for record, copy in zip(output.records[direction], paired[direction], strict=True):
            if copy is not None:
                timing.append(Timing(copy.datagram, copy.kind, "REORDER" in copy.kinds,
                                     record.usec - run.truth.datagrams[copy.datagram].sent_usec))
    return delivery, accounting, OrderScore(inversions, unexplained, tuple(timing))


def _cited(conversion: Conversion, run: Run) -> dict[int, str]:
    """Say how much of each copy's payload the file cites: ``all``, ``some`` or ``none``.

    On the capture path a citation names capture-file bytes, and a copy's
    payload is located by its pieces.  On the packets path it names input
    records whole, so a copy is cited by its frames, headers and all; an
    empty datagram is cited there the same way.
    """
    spans: dict[int | None, list[tuple[int, int]]] = {}
    for space, start, end, _ in conversion.output.undecoded:
        spans.setdefault(space, []).append((start, end))
    out: dict[int, str] = {}
    for copy in run.ledger.copies:
        if conversion.path == "packets":
            ranges = [_frame_range(conversion, run, i) for i in copy.packets]
        else:
            ranges = [(conversion.locate(p.packet, p.at), p.length) for p in copy.pieces]
        total = sum(length for _, length in ranges)
        covered = sum(_covered(spans.get(space, []), start, start + length)
                      for (space, start), length in ranges)
        out[id(copy)] = "none" if covered == 0 else "all" if covered == total and total else "some"
    return out


def _frame_range(
    conversion: Conversion, run: Run, frame: int,
) -> tuple[tuple[int | None, int], int]:
    """Return where a frame's input record sits, and its length, on the packets path."""
    return conversion.frames[frame], len(run.stream.packets[frame].raw) - _ETHERNET


def _covered(spans: list[tuple[int, int]], start: int, end: int) -> int:
    """Count the bytes of ``[start, end)`` that any of *spans* covers."""
    edge = start
    total = 0
    for a, b in sorted(spans):
        lo, hi = max(a, edge), min(b, end)
        if hi > lo:
            total += hi - lo
            edge = hi
    return total


def _spans(conversion: Conversion, run: Run, copy: Copy) -> set[tuple[int, int, int]]:
    """Return the spans a record carrying *copy* should have: one per frame, whole."""
    out = set()
    for frame in copy.packets:
        (space, start), length = _frame_range(conversion, run, frame)
        assert space is not None
        out.add((space, start, start + length))
    return out


def _overtakers(order: list[int]) -> list[int]:
    """Count, for each element of *order*, the earlier elements greater than it.

    Their sum is the number of pairs out of ascending order.  A sorted
    prefix keeps it near-linear for an order that is nearly sorted, as
    a stream's is, where a pair-by-pair count is quadratic in a bulk flow.
    """
    seen: list[int] = []
    out = []
    for value in order:
        out.append(len(seen) - bisect.bisect_right(seen, value))
        bisect.insort(seen, value)
    return out


def _timeline_ok(output: Output) -> bool:
    """Return whether the timeline keeps each direction's stored order, in time order."""
    for direction in DIRECTIONS:
        mine = [r for d, r in output.timeline if d == direction]
        if mine != list(output.records[direction]):
            return False
    times = [r.usec for _, r in output.timeline]
    return times == sorted(times)


def _stats(conversion: Conversion, output: Output, ledger: Ledger) -> tuple[str, ...]:
    """Return where the conversion's stats disagree with the file and the ledger."""
    stats = conversion.stats
    records = [r for d in DIRECTIONS for r in output.records[d]]
    out = []
    if stats.records != len(records):
        out.append(f"stats.records is {stats.records}, the file holds {len(records)}")
    written = sum(len(r.payload) for r in records)
    if stats.payload_bytes != written:
        out.append(f"stats.payload_bytes is {stats.payload_bytes}, the records hold {written}")
    # A datagram withheld before its checksum is read is not counted: on the
    # packets path, a fragmented one (zipline#166).
    read = [c for c in ledger.copies if not (conversion.path == "packets" and c.fragmented)]
    bad = sum(1 for c in read if not c.checksum_ok)
    if stats.bad_checksum != bad:
        out.append(f"stats.bad_checksum is {stats.bad_checksum}, the ledger has {bad}")
    return tuple(out)


def measure(
    run: Run,
    options: ReassemblyOptions | None = None,
    *,
    path: Path = "capture",
    sequenced: bool = False,
) -> Measurement:
    """Convert a run along one path, read it back, and score it.

    A void run is measured all the same: :attr:`Run.void` is what keeps it
    out of a report, and a test may want its numbers regardless.

    Args:
        run: The run.
        options: The reassembly policy; zpfwire's defaults when ``None``.
        path: ``"capture"`` or ``"packets"``.
        sequenced: Whether to ask for causal order.

    Returns:
        The measurement.

    Raises:
        Unclean: If the file does not read back clean.

    """
    conversion = convert(run.stream, options, path=path, sequenced=sequenced)
    delivery, accounting, order = score(run, conversion)
    return Measurement(run, conversion, delivery, accounting, order)

