"""Shared helpers for building synthetic captures in memory.

Captures are built with packeteer's own :class:`PacketBuilder` and written to
a :class:`io.BytesIO`, which is how packeteer tests itself.  It gives exact
control over sequence numbers, retransmits and reordering — the situations a
reassembler has to get right and that a recorded capture cannot be nudged into
on demand.
"""

from __future__ import annotations

import io
import pathlib
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

import zpf
from packeteer.generate import PacketBuilder
from packeteer.generate.tcp import TCP_ACK, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN
from packeteer.pcap import LINKTYPE_ETHERNET, SNAPLEN_UNLIMITED, write_pcap

from zpfwire import ConversionStats, capture_to_zpf

CAPTURES = pathlib.Path(__file__).parent / "captures"

CLIENT_IP = "10.0.0.1"
SERVER_IP = "10.0.0.2"
CLIENT_PORT = 51000
SERVER_PORT = 80

__all__ = [
    "CAPTURES",
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
    "fragmented_frames",
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
) -> bytes:
    """Build one Ethernet/IPv4/TCP frame.

    *checksum* overrides the computed value, which is the only way to write a
    segment that was corrupted on the wire.
    """
    builder = (
        PacketBuilder()
        .ethernet(src_mac="00:00:00:00:00:01", dst_mac="00:00:00:00:00:02")
        .ip(src=src, dst=dst)
        .tcp(src_port=src_port, dst_port=dst_port, seq=seq, ack=ack, flags=flags,
             checksum=checksum)
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
) -> list[bytes]:
    """Build one UDP datagram split across several IPv4 fragments.

    Returns:
        The fragments in wire order; every one is needed to reassemble the
        datagram, so dropping any of them makes it incomplete.

    """
    frames = (
        PacketBuilder()
        .ethernet(src_mac="00:00:00:00:00:01", dst_mac="00:00:00:00:00:02")
        .ip(src=CLIENT_IP, dst=SERVER_IP)
        .udp(src_port=CLIENT_PORT, dst_port=53)
        .payload(data=payload)
        .fragment(mtu)
    )
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

    """

    def __init__(
        self,
        seq: int,
        data: bytes = b"",
        *,
        flags: int = TCP_ACK,
        from_client: bool = True,
    ) -> None:
        self.seq = seq
        self.data = data
        self.flags = flags
        self.from_client = from_client

    def frame(self, *, ack: int = 0) -> bytes:
        """Render this segment as a frame."""
        if self.from_client:
            return tcp_packet(
                src=CLIENT_IP, dst=SERVER_IP,
                src_port=CLIENT_PORT, dst_port=SERVER_PORT,
                seq=self.seq, ack=ack, flags=self.flags, payload=self.data,
            )
        return tcp_packet(
            src=SERVER_IP, dst=CLIENT_IP,
            src_port=SERVER_PORT, dst_port=CLIENT_PORT,
            seq=self.seq, ack=ack, flags=self.flags, payload=self.data,
        )


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
