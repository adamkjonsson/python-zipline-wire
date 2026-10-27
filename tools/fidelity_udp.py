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
"""

from __future__ import annotations

import dataclasses
import ipaddress
import re
import struct
from dataclasses import dataclass

from fidelity_common import BASE_TIME, CLIENT, DIRECTIONS, Direction, kinds_of, payload
from packeteer.generate.impairments import ImpairmentConfig
from packeteer.generate.payloads.base import AppMessage
from packeteer.generate.udp_stream import (
    UDPStream,
    UDPStreamConfig,
    UDPStreamPacket,
    generate_udp_stream,
)
from packeteer.parse import parse_packet

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
