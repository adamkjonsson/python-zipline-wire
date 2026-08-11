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
from dataclasses import dataclass

import zpf
from packeteer.generate import PacketBuilder
from packeteer.generate.tcp import TCP_ACK, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN
from packeteer.pcap import LINKTYPE_ETHERNET, write_pcap

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
) -> bytes:
    """Build one Ethernet/IPv4/TCP frame."""
    builder = (
        PacketBuilder()
        .ethernet(src_mac="00:00:00:00:00:01", dst_mac="00:00:00:00:00:02")
        .ip(src=src, dst=dst)
        .tcp(src_port=src_port, dst_port=dst_port, seq=seq, ack=ack, flags=flags)
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
) -> bytes:
    """Build one Ethernet/IPv4/UDP frame."""
    builder = (
        PacketBuilder()
        .ethernet(src_mac="00:00:00:00:00:01", dst_mac="00:00:00:00:00:02")
        .ip(src=src, dst=dst)
        .udp(src_port=src_port, dst_port=dst_port)
    )
    if payload:
        builder = builder.payload(data=payload)
    return builder.build()


def capture_of(
    frames: Iterable[bytes],
    *,
    start_us: int = 1_000_000,
    step_us: int = 1_000,
    link_type: int = LINKTYPE_ETHERNET,
) -> io.BytesIO:
    """Write *frames* to an in-memory pcap, one timestamp step apart.

    Args:
        frames: Raw frames, in capture order.
        start_us: Timestamp of the first frame, in microseconds since the epoch.
        step_us: Spacing between consecutive frames.
        link_type: Link type recorded in the file header.

    Returns:
        A rewound stream holding the capture.

    """
    records = []
    for index, frame in enumerate(frames):
        stamp = start_us + index * step_us
        records.append((frame, stamp // 1_000_000, stamp % 1_000_000))
    buf = io.BytesIO()
    write_pcap(records, file_object=buf, link_type=link_type)
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

    """

    stats: ConversionStats
    sessions: list[SessionSnapshot]
    diagnostics: list[object]
    path: pathlib.Path

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
    ``zpf.open`` with empty diagnostics is not a conversion, so every test
    goes through this.

    Args:
        source: The capture to convert.
        tmp_path: pytest's temporary directory.
        **kwargs: Passed through to :func:`zpfwire.capture_to_zpf`.

    Returns:
        The stats and the read-back sessions.

    """
    out = pathlib.Path(tmp_path) / "out.zpf"
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
            ))
        diagnostics = list(reader.diagnostics)

    return Converted(stats=stats, sessions=snapshots, diagnostics=diagnostics, path=out)
