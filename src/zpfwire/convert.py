"""Turning a capture into a `.zpf` file.

The output is a **capture-sourced, transport-layer** file: the top-left cell
of the specification's provenance/layer table.  That one fact settles most of
the encoding decisions made here, and the ones it does not are noted where
they are taken.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Callable, Iterable
from typing import IO, Literal

import zpf

from zpfwire.capture import CaptureReader, PacketView
from zpfwire.flow import FlowKey, FlowTracker
from zpfwire.options import DECODER_NAME, ReassemblyOptions, tool_version
from zpfwire.stats import ConversionStats
from zpfwire.tcp import TcpFlow
from zpfwire.udp import UdpFlow

__all__ = ["capture_to_zpf", "convert", "describe_source"]

_TRACKERS: dict[str, type[FlowTracker]] = {"tcp": TcpFlow, "udp": UdpFlow}


def capture_to_zpf(
    source: str | os.PathLike[str] | IO[bytes],
    sink: str | os.PathLike[str] | IO[bytes],
    *,
    options: ReassemblyOptions | None = None,
    tcp: bool = True,
    udp: bool = True,
    tick_hz: int | None = None,
    link_type: int | None = None,
    packet_filter: Callable[[PacketView], bool] | None = None,
    face: Literal["binary", "jsonl"] = "binary",
    sequenced: bool = False,
) -> ConversionStats:
    """Convert a capture file into a `.zpf` file.

    Args:
        source: Path to a pcap or pcapng file, or an open binary stream.
        sink: Path to write, or an open stream.
        options: Reassembly policy; the defaults if omitted.
        tcp: Convert TCP conversations.
        udp: Convert UDP conversations.
        tick_hz: Override the tick rate derived from the capture header.
        link_type: Override the link type for headerless input.
        packet_filter: Called per packet; return ``False`` to exclude it.
        face: ``"binary"`` for a `.zpf`, ``"jsonl"`` for the JSON-Lines
            projection.
        sequenced: Store each TCP session's records in a causal order and
            mark it ``SEQUENCED``.  Costs memory — see :func:`convert`.

    Returns:
        What the conversion did, including everything it could not convert.

    Raises:
        ValueError: If both *tcp* and *udp* are disabled.

    Example:
        >>> stats = capture_to_zpf("capture.pcap", "capture.zpf")
        >>> print(stats.summary())

    """
    if not (tcp or udp):
        raise ValueError("at least one of 'tcp' or 'udp' must be enabled")

    options = options or ReassemblyOptions()
    digest, uri = describe_source(source)
    reader = _open_capture(source, link_type=link_type, tick_hz=tick_hz)
    wanted = {name for name, on in (("tcp", tcp), ("udp", udp)) if on}

    return convert(
        reader,
        sink,
        options=options,
        wanted=wanted,
        digest=digest,
        uri=uri,
        packet_filter=packet_filter,
        face=face,
        sequenced=sequenced,
    )


def convert(
    reader: CaptureReader,
    sink: str | os.PathLike[str] | IO[bytes],
    *,
    options: ReassemblyOptions | None = None,
    wanted: Iterable[str] = ("tcp", "udp"),
    digest: str | None = None,
    uri: str | None = None,
    packet_filter: Callable[[PacketView], bool] | None = None,
    face: Literal["binary", "jsonl"] = "binary",
    sequenced: bool = False,
) -> ConversionStats:
    """Write the packets of an already-open capture as a `.zpf` file.

    The lower-level half of :func:`capture_to_zpf`, for callers that built
    their own :class:`~zpfwire.capture.CaptureReader`.

    Args:
        reader: The capture to convert.
        sink: Path to write, or an open stream.
        options: Reassembly policy; the defaults if omitted.
        wanted: Which transports to convert.
        digest: Content digest of the capture, for the Source Descriptor.
        uri: Where the capture lives, for the Source Descriptor.
        packet_filter: Called per packet; return ``False`` to exclude it.
        face: Output encoding.
        sequenced: Store each TCP session's records in a valid causal order
            and mark it ``SEQUENCED``.  A causal order needs both directions
            of a session in hand, so the session is buffered until it ends —
            unbounded for its lifetime, which is why this is off by default in
            a format whose point is streaming.  Only TCP sessions are marked:
            a TCP session is *hint-ful*, so its order follows from seq and ack
            and needs no ``sequenced_basis``, which a UDP session would.

    Returns:
        What the conversion did.

    """
    options = options or ReassemblyOptions()
    wanted = set(wanted)
    stats = ConversionStats()
    version = tool_version()

    with zpf.create(
        sink,
        tick_hz=reader.tick_hz,
        creator=f"zpfwire {version}",
        produced_by=f"zpfwire {version}",
        # One capture file is one tap, so every timestamp in the output was
        # stamped against one clock. Saying so lets a later stage sequence
        # regrouped streams by time soundly.
        single_clock=True,
        face=face,
    ) as writer:
        # This is the file's only source, so records may omit `source=` and
        # zpf will attribute them to it. The handle is kept because an
        # Undecoded block has to name the input it is talking about.
        source = writer.add_source(
            "capture",
            uri=uri,
            digest=digest,
            link_type=reader.link_type,
        )
        # The specification makes declaring the head-of-pipeline reassembler a
        # SHOULD, and it is the only place the overlap and gap policy can be
        # recorded — which is what makes the conversion reproducible. The
        # layer stays transport; a decoder does not imply a decoded layer.
        decoder = writer.add_decoder(
            DECODER_NAME,
            output_layer=zpf.OutputLayer.TRANSPORT,
            version=version,
            params_digest=options.params_digest(),
        )

        flows: dict[FlowKey, FlowTracker] = {}
        for pkt in reader:
            if pkt.protocol not in wanted:
                stats.skipped[f"{pkt.protocol}-not-requested"] += 1
                continue
            if packet_filter is not None and not packet_filter(pkt):
                stats.filtered += 1
                continue

            key = FlowKey.of(pkt)
            tracker = flows.get(key)
            if tracker is not None and tracker.expired(pkt.ts_ticks):
                tracker.time_out()
                _close(tracker, flows, key)
                tracker = None
            if tracker is None:
                tracker = _begin(writer, key, decoder=decoder, options=options,
                                 stats=stats, tick_hz=reader.tick_hz, source=source,
                                 sequenced=sequenced)
                flows[key] = tracker
                stats.sessions += 1

            tracker.packet(pkt)
            stats.converted += 1

        for key, tracker in list(flows.items()):
            _close(tracker, flows, key)

        # Whatever the reader could not turn into a packet is counted, not lost.
        # Both figures come from the reader rather than the loop above, which
        # only ever sees the packets that survived it.
        stats.packets = reader.packet_count
        stats.skipped.update(reader.skipped)

    return stats


def _begin(
    writer: zpf.FileWriter,
    key: FlowKey,
    *,
    decoder: zpf.DecoderHandle,
    options: ReassemblyOptions,
    stats: ConversionStats,
    tick_hz: int,
    source: zpf.SourceHandle | None = None,
    sequenced: bool = False,
) -> FlowTracker:
    # A TCP session is hint-ful, so its causal order follows from seq/ack
    # alone. `linearize` buffers the session and emits it in that order at
    # end(), which is what lets the reassembler go on producing each direction
    # in its own order — the only order it has.
    causal = sequenced and key.protocol == "tcp"
    session = writer.begin_session(
        proto=key.protocol,
        key=key.text,
        sequenced=causal,
        linearize=causal,
        # A hint-ful session needs no basis, but whether this one *is* hint-ful
        # depends on records that do not exist yet: a TCP conversation of pure
        # acks produces none, and a session with no records is hint-less by
        # default. The specification's answer is to record what the producer
        # relies on rather than what turns out to apply, and SINGLE_CLOCK —
        # which this file sets, one capture being one tap — is exactly the
        # basis that covers those sessions.
        sequenced_basis="clock" if causal else None,
    )
    tracker_type = _TRACKERS[key.protocol]
    return tracker_type(
        key,
        session,
        decoder=decoder,
        options=options,
        stats=stats,
        tick_hz=tick_hz,
        writer=writer,
        source=source,
    )


def _close(tracker: FlowTracker, flows: dict[FlowKey, FlowTracker], key: FlowKey) -> None:
    reason = tracker.finish()
    tracker.session.end(reason=reason)
    flows.pop(key, None)


def _open_capture(
    source: str | os.PathLike[str] | IO[bytes],
    *,
    link_type: int | None,
    tick_hz: int | None,
) -> CaptureReader:
    if isinstance(source, (str, os.PathLike)):
        return CaptureReader(path=source, link_type=link_type, tick_hz=tick_hz)
    source.seek(0)
    return CaptureReader(file_object=source, link_type=link_type, tick_hz=tick_hz)


def describe_source(
    source: str | os.PathLike[str] | IO[bytes],
) -> tuple[str | None, str | None]:
    """Hash a capture so the output can cite what it was derived from.

    The digest is the dependency edge a consumer uses to confirm a `.zpf`
    still matches the capture it came from.

    Args:
        source: Path to a capture, or an open binary stream.

    Returns:
        The ``sha256:`` digest and the URI to record, either of which is
        ``None`` when the source is an unnamed stream.

    """
    if isinstance(source, (str, os.PathLike)):
        digest = hashlib.sha256()
        with open(source, "rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
        return "sha256:" + digest.hexdigest(), os.fspath(source)

    position = source.tell()
    source.seek(0)
    data = source.read()
    source.seek(position)
    return "sha256:" + hashlib.sha256(data).hexdigest(), None
