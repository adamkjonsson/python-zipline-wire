"""Shared helpers for building synthetic captures in memory.

Captures are built with packeteer's own :class:`PacketBuilder` and written to
a :class:`io.BytesIO`, which is how packeteer tests itself.  It gives exact
control over sequence numbers, retransmits and reordering — the situations a
reassembler has to get right and that a recorded capture cannot be nudged into
on demand.
"""

from __future__ import annotations

import hashlib
import io
import pathlib
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

import zpf
from packeteer.generate import PacketBuilder
from packeteer.generate.tcp import TCP_ACK, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN, TCPOptions
from packeteer.parse import iter_packets
from packeteer.pcap import LINKTYPE_ETHERNET, SNAPLEN_UNLIMITED, write_pcap

from zpfwire import ConversionStats, capture_to_zpf

CAPTURES = pathlib.Path(__file__).parent / "captures"
VECTORS = pathlib.Path(__file__).parent / "vectors"

CLIENT_IP = "10.0.0.1"
SERVER_IP = "10.0.0.2"
CLIENT_PORT = 51000
SERVER_PORT = 80

__all__ = [
    "CAPTURES",
    "VECTORS",
    "CLIENT_IP",
    "CLIENT_PORT",
    "SERVER_IP",
    "SERVER_PORT",
    "TCP_ACK",
    "TCP_FIN",
    "TCP_PSH",
    "TCP_RST",
    "TCP_SYN",
    "Converted",
    "Seg",
    "SessionSnapshot",
    "capture_of",
    "decode_digest",
    "packets_zpf",
    "fragmented_frames",
    "is_pure_ack",
    "tcp_packet",
    "tcp_segments",
    "to_zpf",
    "udp_packet",
]


def tcp_packet(
    *,
    src: str = CLIENT_IP,
    dst: str = SERVER_IP,
    src_port: int = CLIENT_PORT,
    dst_port: int = SERVER_PORT,
    seq: int = 0,
    ack: int = 0,
    flags: int = TCP_ACK,
    payload: bytes = b"",
    checksum: int | None = None,
    timestamps: tuple[int, int] | None = None,
) -> bytes:
    """Build one Ethernet/IPv4/TCP frame.

    *checksum* overrides the computed value, which is the only way to write a
    segment that was corrupted on the wire.  *timestamps* is the ``(TSval,
    TSecr)`` pair of the Timestamps option, absent by default.
    """
    options = None if timestamps is None else TCPOptions(timestamps=timestamps)
    builder = (
        PacketBuilder()
        .ethernet(src_mac="00:00:00:00:00:01", dst_mac="00:00:00:00:00:02")
        .ip(src=src, dst=dst)
        .tcp(src_port=src_port, dst_port=dst_port, seq=seq, ack=ack, flags=flags,
             checksum=checksum, options=options)
    )
    if payload:
        builder = builder.payload(data=payload)
    return builder.build()


def udp_packet(
    *,
    src: str = CLIENT_IP,
    dst: str = SERVER_IP,
    src_port: int = CLIENT_PORT,
    dst_port: int = 53,
    payload: bytes = b"",
    checksum: int | None = None,
) -> bytes:
    """Build one Ethernet/IPv4/UDP frame.

    *checksum* overrides the computed value; ``0`` is the legal IPv4 spelling
    of *no checksum was computed*.
    """
    builder = (
        PacketBuilder()
        .ethernet(src_mac="00:00:00:00:00:01", dst_mac="00:00:00:00:00:02")
        .ip(src=src, dst=dst)
        .udp(src_port=src_port, dst_port=dst_port, checksum=checksum)
    )
    if payload:
        builder = builder.payload(data=payload)
    return builder.build()


def fragmented_frames(
    *,
    payload: bytes = b"fragmented-payload" * 80,
    mtu: int = 600,
    identification: int = 0,
    tcp: bool = False,
) -> list[bytes]:
    """Build one UDP datagram, or TCP segment, split across several IPv4 fragments.

    Args:
        payload: The transport payload.
        mtu: The largest IP datagram a fragment may be.
        identification: The IP identification.  ``0`` leaves packeteer to
            draw one, from the unseeded global ``random`` (packeteer#232), so
            a test that reads the ID sets it.
        tcp: Build a TCP segment (PSH, ACK, seq 1) instead of a UDP datagram.

    Returns:
        The fragments in wire order; every one is needed to reassemble the
        datagram, so dropping any of them makes it incomplete.

    """
    builder = (
        PacketBuilder()
        .ethernet(src_mac="00:00:00:00:00:01", dst_mac="00:00:00:00:00:02")
        .ip(src=CLIENT_IP, dst=SERVER_IP, identification=identification)
    )
    if tcp:
        builder = builder.tcp(src_port=CLIENT_PORT, dst_port=80, seq=1, ack=1,
                              flags=TCP_PSH | TCP_ACK)
    else:
        builder = builder.udp(src_port=CLIENT_PORT, dst_port=53)
    frames = builder.payload(data=payload).fragment(mtu)
    assert len(frames) > 1, "the payload must be large enough to fragment"
    return frames


def capture_of(
    frames: Iterable[bytes],
    *,
    start_us: int = 1_000_000,
    step_us: int = 1_000,
    link_type: int = LINKTYPE_ETHERNET,
    snaplen: int | None = None,
) -> io.BytesIO:
    """Write *frames* to an in-memory pcap, one timestamp step apart.

    Args:
        frames: Raw frames, in capture order.
        start_us: Timestamp of the first frame, in microseconds since the epoch.
        step_us: Spacing between consecutive frames.
        link_type: Link type recorded in the file header.
        snaplen: Cut every frame to this many bytes and declare the limit in
            the file header, as ``tcpdump -s`` would.  Each record keeps its
            length on the wire, which is what tells a reader the bytes are
            missing rather than absent.

    Returns:
        A rewound stream holding the capture.

    """
    records: list[tuple[bytes, int, int] | tuple[bytes, int, int, int]] = []
    for index, frame in enumerate(frames):
        stamp = start_us + index * step_us
        sec, frac = stamp // 1_000_000, stamp % 1_000_000
        if snaplen is not None and len(frame) > snaplen:
            records.append((frame[:snaplen], sec, frac, len(frame)))
        else:
            records.append((frame, sec, frac))
    buf = io.BytesIO()
    write_pcap(
        records, file_object=buf, link_type=link_type,
        snaplen=SNAPLEN_UNLIMITED if snaplen is None else snaplen,
    )
    buf.seek(0)
    return buf


class Seg:
    """A TCP segment described relative to a stream, for readable test setup.

    Attributes:
        seq: Absolute sequence number of the first payload byte.
        data: Payload bytes.
        flags: TCP flags to set in addition to ACK.
        from_client: Direction the segment travels.
        timestamps: The ``(TSval, TSecr)`` pair, or ``None`` for no option.
        ack: The acknowledgement number, or ``None`` to take :meth:`frame`'s.

    """

    def __init__(
        self,
        seq: int,
        data: bytes = b"",
        *,
        flags: int = TCP_ACK,
        from_client: bool = True,
        timestamps: tuple[int, int] | None = None,
        ack: int | None = None,
    ) -> None:
        self.seq = seq
        self.data = data
        self.flags = flags
        self.from_client = from_client
        self.timestamps = timestamps
        self.ack = ack

    def frame(self, *, ack: int = 0) -> bytes:
        """Render this segment as a frame."""
        if self.ack is not None:
            ack = self.ack
        if self.from_client:
            return tcp_packet(
                src=CLIENT_IP, dst=SERVER_IP,
                src_port=CLIENT_PORT, dst_port=SERVER_PORT,
                seq=self.seq, ack=ack, flags=self.flags, payload=self.data,
                timestamps=self.timestamps,
            )
        return tcp_packet(
            src=SERVER_IP, dst=CLIENT_IP,
            src_port=SERVER_PORT, dst_port=CLIENT_PORT,
            seq=self.seq, ack=ack, flags=self.flags, payload=self.data,
            timestamps=self.timestamps,
        )


def is_pure_ack(record: zpf.Record) -> bool:
    """Say whether *record* is a stored pure ACK: no bytes, no flags, an ``ack``.

    The SYN record is zero-length too, but carries ``syn``; a pure ACK
    carries nothing but its hints (#37).
    """
    return record.payload == b"" and not record.flags and record.ack is not None


def tcp_segments(segments: Sequence[Seg], **kwargs: int) -> io.BytesIO:
    """Write a sequence of :class:`Seg` objects to an in-memory pcap."""
    return capture_of([seg.frame() for seg in segments], **kwargs)


@dataclass
class Converted:
    """A conversion result, already read back.

    Attributes:
        stats: What the conversion reported.
        sessions: The sessions in the written file.
        diagnostics: Anything the reader objected to — must be empty.
        path: Where the file was written.
        undecoded: The Undecoded regions the file cites.
        unplaceable: Records the offset space could not place — must be
            empty.  Reported apart from *diagnostics* because since spec
            ``0.19`` such a record breaks no rule, so a file carrying one
            still reads clean; a producer writing one is discarding its own
            bytes all the same.

    """

    stats: ConversionStats
    sessions: list[SessionSnapshot]
    diagnostics: list[object]
    path: pathlib.Path
    undecoded: list[object] = field(default_factory=list)
    unplaceable: list[object] = field(default_factory=list)

    @property
    def only(self) -> SessionSnapshot:
        """The single session, asserting there is exactly one."""
        assert len(self.sessions) == 1, f"expected one session, got {len(self.sessions)}"
        return self.sessions[0]


@dataclass
class SessionSnapshot:
    """One session, read back out of a written file."""

    proto: str
    key: str | None
    participants: tuple[object, ...]
    records: list[object]
    end_reason: str | None
    sequenced: bool = False

    def by(self, pid: int) -> list[object]:
        """Return the records sent by participant *pid*, in stored order."""
        return [r for r in self.records if r.sender_pid == pid]

    def stream(self, pid: int) -> bytes:
        """Concatenated payload of participant *pid*'s records."""
        return b"".join(r.payload for r in self.by(pid))

    def participant(self, endpoint: str) -> object:
        """Return the participant declared with *endpoint*."""
        for p in self.participants:
            if p.endpoint == endpoint:
                return p
        raise KeyError(endpoint)


def to_zpf(source: io.BytesIO | pathlib.Path | str, tmp_path: pathlib.Path,
           **kwargs: object) -> Converted:
    """Convert a capture and read the result straight back.

    Reading back is not incidental: a file that does not survive
    ``zpf.open`` with empty diagnostics *and* nothing unplaceable is not a
    conversion, so every test goes through this.

    Args:
        source: The capture to convert.
        tmp_path: pytest's temporary directory.
        **kwargs: Passed through to :func:`zpfwire.capture_to_zpf`.

    Returns:
        The stats and the read-back sessions.

    """
    directory = pathlib.Path(tmp_path)
    directory.mkdir(parents=True, exist_ok=True)
    out = directory / "out.zpf"
    stats = capture_to_zpf(source, out, **kwargs)  # type: ignore[arg-type]

    snapshots: list[SessionSnapshot] = []
    with zpf.open(out) as reader:
        for session in reader.sessions():
            snapshots.append(SessionSnapshot(
                proto=session.proto,
                key=session.key,
                participants=tuple(session.participants),
                records=list(session.records()),
                end_reason=session.end.reason if session.end else None,
                sequenced=bool(session.sequenced),
            ))
        undecoded = list(reader.undecoded)
        diagnostics = list(reader.diagnostics)
        unplaceable = list(reader.unplaceable)

    return Converted(stats=stats, sessions=snapshots, diagnostics=diagnostics, path=out,
                     undecoded=undecoded, unplaceable=unplaceable)


def decode_digest(path: pathlib.Path | str) -> str:
    """Digest what the reassembler decided, and nothing else.

    A whole-file hash would pin three things that move without a byte of
    reassembly moving: the wall-clock ``produced_at``, the tool version in
    ``produced_by``, and the capture's path in the Source ``uri``.  This
    hashes every block in stored order with those taken out — the File
    Header dropped, the Source reduced to the capture's own digest and link
    type, the Decoder to its name, output layer and ``params_digest`` — so
    two files agree exactly when the same records, hints, flags, timestamps,
    participants, session ends and Undecoded citations were written in the
    same order under the same declared policy.

    Args:
        path: A ``.zpf`` file.

    Returns:
        A ``sha256:`` digest.

    """
    h = hashlib.sha256()
    with zpf.open(path) as reader:
        for block in reader.blocks():
            if isinstance(block, zpf.FileHeader):
                continue
            if isinstance(block, zpf.Source):
                canonical = f"source {block.kind} {block.digest} {block.link_type}".encode()
            elif isinstance(block, zpf.Decoder):
                canonical = (
                    f"decoder {block.name} {block.output_layer} {block.params_digest}".encode()
                )
            else:
                canonical = block.to_bytes()
            h.update(block.block_type.to_bytes(2, "little"))
            h.update(len(canonical).to_bytes(4, "little"))
            h.update(canonical)
    return "sha256:" + h.hexdigest()


def packets_zpf(
    capture: pathlib.Path | str | io.BytesIO,
    out: pathlib.Path,
    *,
    adjacency: zpf.Adjacency = zpf.Adjacency.UNITS,
    label: str = zpf.NET_IP,
    fields: bool = True,
    interleave: bool = False,
) -> pathlib.Path:
    """Write a capture's packets as a `.zpf` of packet records — what a tunnel decryptor writes.

    One session and two participants, standing for a tunnel's two
    directions; each frame becomes one record labelled *label*.  Under
    ``net:ethernet`` the record is the whole frame; under any other label it
    is the frame from its IP header on, Ethernet padding included, as
    zipline-kober's WireGuard decode keeps WireGuard's.  A frame with no IP
    header is a ``prim:bytes`` record, which is not a packet.  It is a
    capture-sourced *decoded* file, a legal cell of the
    specification's two axes, so it needs no ``.zpf`` of its own to derive
    from — and so its records cite nothing, since a span may only name a
    ``.zpf`` input.

    Args:
        capture: The capture to repackage.
        out: Where to write the ``.zpf``.
        adjacency: ``UNITS`` for zipline-kober's field-granular shape, or
            ``CONTIGUOUS``, which also gets one Discontinuity half way
            through the first participant — the vector's shape.
        label: The packets' ``content_type``.
        fields: Interleave a one-byte ``prim:u8`` record before each packet,
            as a field-granular decode writes its header fields, so that
            selection by label is exercised.
        interleave: Store the two participants' records interleaved in
            capture order.  By default one participant's are all stored
            before the other's, as zipline-kober stores them, so a reader
            that trusts the file's stored order across participants is
            caught; interleaving gives the same records another order.

    Returns:
        *out*.

    """
    where = {"file_object": capture} if isinstance(capture, io.BytesIO) else {"path": capture}
    if isinstance(capture, io.BytesIO):
        capture.seek(0)
    with iter_packets(**where, decode_app=False, defragment=False) as packets:  # type: ignore[arg-type]
        tick_hz = packets.header.tick_hz
        link_type = packets.header.link_type
        frames = [(p.ts_sec * tick_hz + p.ts_frac, p, p.source_records[0]) for p in packets]
    sides: dict[int, list[tuple[int, bytes, str]]] = {0: [], 1: []}
    stored: list[tuple[int, int]] = []
    for ts, packet, record in frames:
        side = 0 if packet.ip is None or packet.ip.src <= packet.ip.dst else 1
        frame = record.data
        ip_at = packet.offsets.get("ip")
        if label == zpf.NET_ETHERNET:
            payload, content_type = frame, label
        elif ip_at is None:
            payload, content_type = frame, "prim:bytes"
        else:
            payload, content_type = frame[ip_at:], label
        if fields:
            stored.append((side, len(sides[side])))
            sides[side].append((ts, frame[:1], "prim:u8"))
        stored.append((side, len(sides[side])))
        sides[side].append((ts, payload, content_type))
    if not interleave:
        stored = [(side, i) for side in (0, 1) for i in range(len(sides[side]))]

    with zpf.create(out, tick_hz=tick_hz, produced_by="zpfwire tests",
                    produced_at=1_700_000_000) as writer:
        uri = None if isinstance(capture, io.BytesIO) else str(capture)
        writer.add_source("capture", uri=uri, link_type=link_type)
        decoder = writer.add_decoder("tunnel", output_layer=zpf.OutputLayer.DECODED,
                                     version="0")
        session = writer.begin_session(proto="ip", key="tunnel")
        handles = [session.participant(f"tunnel-{side}", adjacency=adjacency) for side in (0, 1)]
        middle = len(sides[0]) // 2
        for side, i in stored:
            ts, payload, content_type = sides[side][i]
            if adjacency == zpf.Adjacency.CONTIGUOUS and side == 0 and i == middle:
                session.discontinuity(handles[side], reason="decrypt-failed")
            session.record(
                handles[side], ts=ts, payload=payload,
                decoded=zpf.Decoded(decoder=decoder, content_type=content_type),
            )
        session.end()
    return out
