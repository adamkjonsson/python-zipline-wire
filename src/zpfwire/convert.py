"""Turning a capture into a `.zpf` file.

The output is a **capture-sourced, transport-layer** file: the top-left cell
of the specification's provenance/layer table.  That one fact settles most of
the encoding decisions made here, and the ones it does not are noted where
they are taken.
"""

from __future__ import annotations

import datetime
import hashlib
import os
from collections.abc import Callable, Iterable
from typing import IO, Literal

import zpf

from zpfwire.capture import CaptureReader, PacketView
from zpfwire.flow import REASON_CHECKSUM, FlowKey, FlowTracker, cite_undecoded
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
    produced_at: int | datetime.datetime | Literal["now"] | None = "now",
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
        produced_at: When this file was built — see :func:`convert`.  Pin it
            to make two conversions of one capture byte-identical.

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
        produced_at=produced_at,
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
    produced_at: int | datetime.datetime | Literal["now"] | None = "now",
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
            a TCP session's order follows from seq and ack, which is a claim
            the capture supports, where a UDP session's would rest on the
            clock alone — a different claim, and not one this tool makes on a
            caller's behalf.
        produced_at: When this file was built.  ``"now"`` stamps the
            conversion, an ``int`` (Unix seconds) or timezone-aware
            :class:`~datetime.datetime` pins it, and ``None`` omits it.

            Since spec ``0.19`` this is where the forensic account of a file
            lives: a ``SEQUENCED`` session no longer records what its order
            rests on, the producer being trusted for the basis exactly as it
            already was for the order, so the build provenance beside
            ``produced_by`` is what a consumer has to go on.

            It is also the only part of the output that is not a function of
            the input, so two conversions of one capture differ by the stamp
            alone.  Pin it where that matters; the reproducibility of the
            *decode* is unaffected either way, being carried by the Decoder's
            ``params_digest``.

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
        produced_at=_produced_at(produced_at),
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
            comment=_source_comment(reader),
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
            if pkt.checksum_bad:
                stats.bad_checksum += 1
                if options.checksum == "drop":
                    _drop(pkt, writer, source, decoder=decoder, stats=stats)
                    continue

            key = FlowKey.of(pkt)
            tracker = flows.get(key)
            if tracker is not None and tracker.expired(pkt.ts_ticks):
                tracker.time_out()
                _close(tracker, flows, key)
                tracker = None
            elif tracker is not None and tracker.splits_before(pkt):
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
            if pkt.truncated:
                stats.truncated += 1

        for key, tracker in list(flows.items()):
            _close(tracker, flows, key)

        # Whatever the reader could not turn into a packet is counted, not lost.
        # Both figures come from the reader rather than the loop above, which
        # only ever sees the packets that survived it.
        stats.packets = reader.packet_count
        stats.skipped.update(reader.skipped)

    return stats


def _produced_at(
    value: int | datetime.datetime | Literal["now"] | None,
) -> int | datetime.datetime | None:
    """Resolve the build stamp, ``"now"`` meaning this moment.

    ``None`` passes straight through, keeping the meaning it has on
    :func:`zpf.create` — the field is absent.

    Returns:
        What to stamp the File Header with, or ``None`` to stamp nothing.

    """
    if value == "now":
        return datetime.datetime.now(tz=datetime.timezone.utc)
    return value


def _source_comment(reader: CaptureReader) -> str | None:
    """Say what the capture's snaplen was, when it had one.

    A snaplen is provenance of the same kind as the link type — it says what
    the capture *is* — and it is what explains payloads shorter than what was
    sent.  The Source Descriptor has no field for it, so it goes in the block's
    free-text comment.  A field or TLV of its own would be the better home,
    beside ``link_type``; that is a specification change, not one to make here.

    Returns:
        ``"snaplen=262144"``, or ``None`` when the capture states no limit.

    """
    if reader.snaplen is None:
        return None
    return f"snaplen={reader.snaplen}"


def _drop(
    pkt: PacketView,
    writer: zpf.FileWriter,
    source: zpf.SourceHandle | None,
    *,
    decoder: zpf.DecoderHandle,
    stats: ConversionStats,
) -> None:
    """Discard a packet whose checksum did not verify, the way a receiver does.

    The whole packet goes, not just its payload: a receiver that fails the
    checksum has no reason to trust the header either, so the segment's flags
    open and close nothing.  Dropping it before the flow lookup also keeps a
    corrupt packet from being the one that starts a session.

    The payload is cited as an Undecoded region like any other bytes that
    exist in the capture and reach no record, and the packet is tallied as a
    skip so that every packet is still converted, skipped or filtered.
    """
    stats.skipped[REASON_CHECKSUM] += 1
    stats.checksum_dropped_bytes += len(pkt.payload)
    cite_undecoded(
        writer, source, pkt.payload_offset, len(pkt.payload),
        reason=REASON_CHECKSUM, decoder=decoder, stats=stats,
    )


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
    # A TCP session's causal order follows from seq/ack alone. `linearize`
    # buffers the session and emits it in that order at end(), which is what
    # lets the reassembler go on producing each direction in its own order —
    # the only order it has.
    causal = sequenced and key.protocol == "tcp"
    session = writer.begin_session(
        proto=key.protocol,
        key=key.text,
        sequenced=causal,
        linearize=causal,
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
