"""Converting a `.zpf` of packets into sessions.

A stage that decrypts a tunnel leaves its inner traffic as **records, not a
capture**: one record per inner packet, labelled ``net:ip`` (or
``net:ethernet``) since spec ``0.22``.  This module is the next hop of the
specification's decrypted-tunnel chain, ``packets.zpf → inner.zpf``: the same
reassembly a capture gets, run over those records, writing a transport-layer
file whose every record cites the input packets it was built from.

The output is written through :func:`zpf.sessionize_stage`, which owns what
makes such a file honest without this tree's help: the ``zpf-input`` Source,
the Decoder at the transport layer, coverage per input stream across every
output session, the ``skipped`` auto-fill of whatever nothing cited or
marked, and each Session End's whole-stream ``input_extents``.  What it
deliberately does not do is parse packets, track flows or decide what a
discard was — the parts that are this tree's on a capture too, and are
shared with it here (:mod:`zpfwire.convert`).

A packet is cited **whole**, headers included, by every record its bytes or
its flags reached: the headers are what placed the bytes in the stream, so
they fed the record, which is the specification's test (*correspondence,
not proximity*).  A packet that reached no record is either marked with the
reason this tree discarded it — ``duplicate-discarded``, ``late-arrival``,
``bad-checksum`` and the rest, as on a capture — or, if nothing discarded
it (a pure ACK, a filtered flow, a record that is not a packet), left to
the stage's ``skipped`` auto-fill.
"""

from __future__ import annotations

import datetime
import heapq
import os
from collections import Counter
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import IO, Literal, Protocol

import zpf
from packeteer.generate.udp import UDPHeader
from packeteer.parse import AssembledFrame, Defragmenter, parse_packet, supports_link_type
from packeteer.pcap import LINKTYPE_RAW, write_pcap

from zpfwire.capture import PacketView, SkipReason, packet_view, skip_reason
from zpfwire.convert import _drive, _produced_at
from zpfwire.flow import FlowKey, RecordSink
from zpfwire.options import DECODER_NAME, ReassemblyOptions, tool_version
from zpfwire.stats import ConversionStats

__all__ = [
    "REASON_UNDECODABLE",
    "SKIP_FRAGMENTED_UDP",
    "PacketRecordReader",
    "PacketSink",
    "PcapExport",
    "input_kind",
    "packets_to_pcap",
    "packets_to_zpf",
]

REASON_UNDECODABLE = "undecodable"
"""Undecoded reason for a selected record that did not become a packet.

The specification's canonical word for *the stage tried and failed*: a
record labelled as a packet whose IP or transport header did not parse, a
fragment of a datagram that never completed, or a UDP datagram reassembled
from fragments, which no conformant record can cite (see
:data:`SKIP_FRAGMENTED_UDP`).  Its ``comment`` says which.
"""

SKIP_FRAGMENTED_UDP = "fragmented-udp"
"""Skip key for a UDP datagram reassembled from several input records.

A UDP record carries no ``seq_start``, and since spec ``0.22`` only a record
that does may cite several input units: its sequence numbers are what assert
that they join.  So a datagram rebuilt from fragments has no conformant
record, and its fragments are marked :data:`REASON_UNDECODABLE`
(`zipline#166 <https://github.com/adamkjonsson/zipline/issues/166>`_).
Fragmented TCP is unaffected: the segment's record carries ``seq_start``.
"""

_BYTES_EXIST = "bytes"
"""The ``reason_class`` of everything this tree marks: the input bytes exist."""

# A packet is named by a number that is also a `payload_offset`, so that every
# offset the reassembler computes — a packet's payload offset plus how far
# into the payload — still names the packet it is in.  The low 32 bits are
# that skip; above them, the packet: its input stream (counted from 1), and
# the record's offset and length in that stream.  A packet reassembled from
# several records has stream 0 and an index into a table of their parts.
_SKIP_BITS = 32
_LENGTH_BITS = 32
_OFFSET_BITS = 64
_MASK_LENGTH = (1 << _LENGTH_BITS) - 1
_MASK_OFFSET = (1 << _OFFSET_BITS) - 1

_Part = tuple[int, int, int]
"""One input range a packet came from: ``(stream index, off_start, off_end)``."""

_Mark = Callable[[Sequence[_Part], str, str | None], None]
"""Declare input ranges undecoded: ``(parts, reason, comment)``."""

_Keyed = tuple[tuple[int, int, int], int, zpf.Datagram]
"""An input record with its merge key and its stream's index."""


class _Datagrams(Protocol):
    """An input stream read one record at a time: a stage's or a plain reader's view."""

    def datagrams(self) -> Iterator[zpf.Datagram]:
        """Yield the stream's records in stored order."""
        ...  # pragma: no cover


def _merged(streams: Sequence[_Datagrams]) -> Iterator[tuple[int, zpf.Datagram]]:
    """Yield every record of *streams*, with its stream's index, in timestamp order.

    A decrypting stage writes one participant per tunnel direction and stores
    one direction's records before the other's, so the file's stored order is
    not wire order.  Each stream is read lazily, in its own stored order,
    and the streams are merged by timestamp; ties break on the stream's
    index and then the record's offset, so the order is total.
    """
    def keyed(index: int, stream: _Datagrams) -> Iterator[_Keyed]:
        for datagram in stream.datagrams():
            yield (datagram.ts, index, datagram.off_start), index, datagram

    for _key, index, datagram in heapq.merge(*(keyed(i, s) for i, s in enumerate(streams))):
        yield index, datagram


class _Origins:
    """Names input packets by numbers a reassembler can do arithmetic on.

    See the comment above :data:`_SKIP_BITS` for the layout.  A packet from
    one input record is named by the number alone, with nothing stored; only
    a packet reassembled from fragments keeps an entry, since several ranges
    do not fit in one number, and the table is kept for the conversion.
    """

    def __init__(self, streams: Sequence[zpf.InputStream]) -> None:
        self._streams = list(streams)
        self._fragmented: list[tuple[_Part, ...]] = []

    def slot(self, parts: Sequence[_Part]) -> int:
        """Return the number naming the packet built from *parts*."""
        if len(parts) == 1:
            ((index, start, end),) = parts
            tag, offset, length = index + 1, start, end - start
        else:
            tag, offset, length = 0, len(self._fragmented), 0
            self._fragmented.append(tuple(parts))
        return ((((tag << _OFFSET_BITS) | offset) << _LENGTH_BITS) | length) << _SKIP_BITS

    @staticmethod
    def packet_of(offset: int) -> int:
        """Return the number naming the packet *offset* falls in."""
        return (offset >> _SKIP_BITS) << _SKIP_BITS

    def parts(self, offset: int) -> tuple[_Part, ...]:
        """Return the input ranges of the packet *offset* falls in."""
        named = offset >> _SKIP_BITS
        length = named & _MASK_LENGTH
        rest = named >> _LENGTH_BITS
        start, tag = rest & _MASK_OFFSET, rest >> _OFFSET_BITS
        if tag == 0:
            return self._fragmented[start]
        return ((tag - 1, start, start + length),)

    def stream(self, index: int) -> zpf.InputStream:
        """Return the input stream a part names."""
        return self._streams[index]

    def spans(self, slots: Iterable[int]) -> list[zpf.Span]:
        """Cite the packets *slots* name, merging ranges that abut in one stream."""
        parts = sorted(part for slot in slots for part in self.parts(slot))
        merged: list[list[int]] = []
        for index, start, end in parts:
            if merged and merged[-1][0] == index and merged[-1][2] >= start:
                merged[-1][2] = max(merged[-1][2], end)
            else:
                merged.append([index, start, end])
        return [self._streams[index].cite(start, end) for index, start, end in merged]


class PacketRecordReader:
    """Iterates the packet records of a `.zpf` as :class:`~zpfwire.capture.PacketView` objects.

    The counterpart of :class:`~zpfwire.capture.CaptureReader` for an input
    that is a ``.zpf`` of packets.  Records are selected by ``content_type``,
    merged across every input stream into timestamp order — a decrypting
    stage writes one participant per tunnel direction and stores one
    direction's records before the other's, so stored order is not wire
    order — defragmented, and parsed as the link type their label names.
    The merge streams: each input stream is read lazily, side by side.

    Attributes:
        tick_hz: Ticks per second of every timestamp, the input's own.
        packet_count: Packets seen during the most recent iteration,
            including those that turned out not to be TCP or UDP.  A datagram
            reassembled from several records counts once, as in
            :attr:`~zpfwire.capture.CaptureReader.packet_count`.
        skipped: Tally of why selected records produced no packet, keyed by
            :class:`~zpfwire.capture.SkipReason` and
            :data:`SKIP_FRAGMENTED_UDP`.
        records_read: Records in the input.
        records_selected: Records whose label selected them.

    """

    def __init__(
        self,
        streams: Sequence[zpf.InputStream],
        *,
        tick_hz: int,
        select: Mapping[str, int],
        origins: _Origins,
        mark: _Mark,
    ) -> None:
        """Prepare to read packets from *streams*.

        Args:
            streams: The input streams, from :meth:`zpf.SessionizeStage.streams`.
            tick_hz: The input's ticks per second.
            select: The labels that make a record a packet, each with the
                link type its bytes are parsed as.
            origins: How a packet is named to the reassembler.
            mark: Where a record that did not become a packet is declared
                undecoded.

        """
        self.tick_hz = tick_hz
        self.packet_count = 0
        self.skipped: Counter[str] = Counter()
        self.records_read = 0
        self.records_selected = 0
        self._streams = list(streams)
        self._select = dict(select)
        self._origins = origins
        self._mark = mark

    def __iter__(self) -> Iterator[PacketView]:
        """Yield a view of every TCP segment and UDP datagram the selected records carry."""
        self.packet_count = self.records_read = self.records_selected = 0
        self.skipped.clear()
        engines: dict[int, Defragmenter] = {}
        for index, datagram in _merged(self._streams):
            self.records_read += 1
            link_type = self._select.get(datagram.record.content_type or "")
            if link_type is None:
                continue
            self.records_selected += 1
            engine = engines.get(link_type)
            if engine is None:
                engine = engines[link_type] = Defragmenter(link_type=link_type)
            part = (index, datagram.off_start, datagram.off_end)
            for assembled in engine.feed(datagram.data, datagram.ts / self.tick_hz, token=part):
                self.packet_count += 1
                view = self._view(assembled, link_type, datagram.ts)
                if view is not None:
                    yield view
        for engine in engines.values():
            engine.flush()
            for lost in engine.incomplete:
                self.skipped[SkipReason.INCOMPLETE_DATAGRAM] += 1
                self._mark(lost.tokens, REASON_UNDECODABLE,
                           f"a fragment of a datagram that never completed ({lost.reason})")

    def _view(self, assembled: AssembledFrame, link_type: int, ts: int) -> PacketView | None:
        """Parse one whole packet, or account for why it is not one."""
        parts: list[_Part] = list(assembled.tokens)
        packet = parse_packet(assembled.frame, link_type=link_type, decode_app=False)
        reason = skip_reason(packet, headerless=link_type == LINKTYPE_RAW)
        if reason is not None:
            self.skipped[reason] += 1
            if reason in (SkipReason.MALFORMED_IP, SkipReason.MALFORMED_TRANSPORT):
                self._mark(parts, REASON_UNDECODABLE, f"labelled a packet, but {reason}")
            return None
        if len(parts) > 1 and isinstance(packet.transport, UDPHeader):
            self.skipped[SKIP_FRAGMENTED_UDP] += 1
            self._mark(parts, REASON_UNDECODABLE,
                       f"a UDP datagram reassembled from {len(parts)} records, which no record "
                       "without seq_start may cite (zipline#166)")
            return None
        return packet_view(
            packet,
            packet_num=self.packet_count,
            ts_ticks=ts,
            payload_offset=self._origins.slot(parts),
            fragment_count=assembled.fragment_count,
        )


class PacketSink(RecordSink):
    """A sessionization stage's session: records citing input packets, discards marked on them.

    A packet is cited by a record when any of its bytes or its flags reach
    one.  A discard is only *noted* when it happens, because a packet can be
    trimmed before the rest of it is kept — a repeat's leading overlap, say
    — and a range cited and marked both is a contradiction the stage
    refuses.  When the session ends, every packet that was discarded and
    never cited is marked, with the reason of its first discard.

    Attributes:
        flow: The output session being written.

    """

    def __init__(
        self,
        flow: zpf.FlowSession,
        *,
        origins: _Origins,
        mark: _Mark,
        stats: ConversionStats,
    ) -> None:
        """Bind a sink to one output session.

        Args:
            flow: The stage's session for this flow.
            origins: How packets are named.
            mark: Where discarded packets are declared undecoded.
            stats: Tally of what was written.

        """
        self.flow = flow
        self._origins = origins
        self._mark = mark
        self._stats = stats
        self._discarded: dict[int, str] = {}

    def participant(self, endpoint: str, **declaration: object) -> zpf.ParticipantHandle:
        """Declare a participant of the output session.

        Args:
            endpoint: The participant's ``ip:port``.
            **declaration: ``isn`` and ``tcp_role``, where known.

        Returns:
            The participant handle.

        """
        return self.flow.participant(endpoint, **declaration)  # type: ignore[arg-type]

    def record(
        self,
        sender: zpf.ParticipantHandle,
        *,
        ts: int,
        payload: bytes,
        origins: Sequence[int | None],
        hints: zpf.Hints | None = None,
        flags: zpf.RecordFlags | int = 0,
        ts_first: int | None = None,
    ) -> None:
        """Write one record citing every packet in *origins*.

        Args:
            sender: The participant that sent the bytes.
            ts: The record's timestamp, in ticks.
            payload: The record's bytes.
            origins: The ``payload_offset`` of every packet it was built from.
            hints: ``seq_start`` and ``ack``, for TCP.
            flags: The record's flags.
            ts_first: When the first contributing packet arrived.

        """
        slots = {_Origins.packet_of(origin) for origin in origins if origin is not None}
        for slot in slots:
            self._discarded.pop(slot, None)
        self.flow.record(
            sender, payload, cites=self._origins.spans(slots),
            ts=ts, ts_first=ts_first, hints=hints, flags=flags,
        )

    def undecoded(self, off_start: int | None, length: int, *, reason: str) -> None:
        """Note that a packet lost bytes, to mark it at the end unless a record cites it.

        Args:
            off_start: A ``payload_offset`` plus how far into that payload.
            length: How many bytes were discarded.
            reason: Why.

        """
        if length <= 0:
            return
        if off_start is None:
            self._stats.unlocatable_bytes += length
            return
        self._discarded.setdefault(_Origins.packet_of(off_start), reason)

    def end(self, reason: str) -> None:
        """Mark every packet discarded and never cited, then end the session.

        Args:
            reason: How it ended.

        """
        for slot, why in self._discarded.items():
            self._mark(self._origins.parts(slot), why, None)
        self._discarded.clear()
        self.flow.end(reason)


class _PacketTarget:
    """A sessionization stage as a conversion's output: a stage session per flow."""

    def __init__(
        self,
        stage: zpf.SessionizeStage,
        *,
        origins: _Origins,
        mark: _Mark,
        stats: ConversionStats,
    ) -> None:
        self._stage = stage
        self._origins = origins
        self._mark = mark
        self._stats = stats

    def begin(self, key: FlowKey, *, sequenced: bool) -> RecordSink:
        # As for a capture: only a TCP session's order follows from the
        # packets themselves, so only a TCP session is sequenced.
        causal = sequenced and key.protocol == "tcp"
        flow = self._stage.session(key.text, proto=key.protocol, sequenced=causal)
        return PacketSink(flow, origins=self._origins, mark=self._mark, stats=self._stats)

    def drop(self, pkt: PacketView, *, reason: str) -> None:
        if pkt.payload_offset is not None:
            self._mark(self._origins.parts(pkt.payload_offset), reason, None)


def packets_to_zpf(
    source: str | os.PathLike[str] | IO[bytes],
    sink: str | os.PathLike[str] | IO[bytes],
    *,
    content_type: str | None = None,
    link_type: int | None = None,
    options: ReassemblyOptions | None = None,
    tcp: bool = True,
    udp: bool = True,
    packet_filter: Callable[[PacketView], bool] | None = None,
    face: Literal["binary", "jsonl"] = "binary",
    sequenced: bool = False,
    produced_at: int | datetime.datetime | Literal["now"] = "now",
) -> ConversionStats:
    """Convert a `.zpf` of packets into a `.zpf` of the sessions inside them.

    The counterpart of :func:`~zpfwire.convert.capture_to_zpf` for a
    ``.zpf`` input: the same keywords, less the two a ``.zpf`` states itself
    (``tick_hz`` and the capture's ``link_type``), plus the selection.

    Args:
        source: Path to the input ``.zpf``, binary or JSONL, or an open
            binary stream.
        sink: Path to write, or an open binary stream.
        content_type: The label that makes a record a packet.  ``None``, the
            default, selects both of the format's own, ``net:ip`` and
            ``net:ethernet``, each parsed as the link type it names.  Any
            other label — a decoder's private ``dec:ip-packet``, say — is
            parsed as *link_type*.
        link_type: The link type of records selected by a *content_type*
            outside ``net:``; ``LINKTYPE_RAW`` (raw IP) if omitted.  Refused
            alongside a ``net:`` label it disagrees with.
        options: Reassembly policy; the defaults if omitted.
        tcp: Convert TCP conversations.
        udp: Convert UDP conversations.
        packet_filter: Called per packet; return ``False`` to exclude it.
        face: ``"binary"`` only, for now: the stage writing the output takes
            no face (`python-zipline#89
            <https://github.com/adamkjonsson/python-zipline/issues/89>`_).
        sequenced: Store each TCP session's records in a causal order and
            mark it ``SEQUENCED``; see :func:`~zpfwire.convert.convert`.
        produced_at: When this file was built: ``"now"``, an ``int`` (Unix
            seconds) or a timezone-aware :class:`~datetime.datetime`.  A
            derived file must carry it, so it cannot be omitted; pin it to
            make two conversions of one input byte-identical.

    Returns:
        What the conversion did.

    Raises:
        ValueError: If both *tcp* and *udp* are disabled, *face* is
            ``"jsonl"``, *produced_at* is ``None``, or the selection is
            inconsistent or names a link type packeteer cannot parse.

    Example:
        >>> stats = packets_to_zpf("packets.zpf", "inner.zpf")
        >>> print(stats.summary())

    """
    if not (tcp or udp):
        raise ValueError("at least one of 'tcp' or 'udp' must be enabled")
    if face != "binary":
        raise ValueError(
            "a .zpf input is written in the binary face only, until the sessionization "
            "stage takes one (python-zipline#89)"
        )
    if produced_at is None:
        raise ValueError("a file derived from a .zpf must say when it was built; pass produced_at")
    select = _selection(content_type, link_type)
    options = options or ReassemblyOptions()
    stats = ConversionStats()
    version = tool_version()
    wanted = {name for name, on in (("tcp", tcp), ("udp", udp)) if on}
    labels = ", ".join(sorted(select))

    with zpf.sessionize_stage(
        source,
        sink,
        decoder=(DECODER_NAME, version),
        produced_by=f"zpfwire {version}",
        produced_at=_produced_at(produced_at),  # type: ignore[arg-type]
        params_digest=options.params_digest(),
        comment=f"packets: the input records labelled {labels}",
    ) as stage:
        streams = stage.streams()
        origins = _Origins(streams)

        def mark(parts: Sequence[_Part], reason: str, comment: str | None) -> None:
            for index, start, end in parts:
                stage.undecoded(origins.stream(index), start, end, reason=reason,
                                reason_class=_BYTES_EXIST, comment=comment)
                stats.undecoded_regions += 1

        reader = PacketRecordReader(
            streams, tick_hz=stage.reader.header.tick_hz, select=select,
            origins=origins, mark=mark,
        )
        target = _PacketTarget(stage, origins=origins, mark=mark, stats=stats)
        _drive(reader, target, options=options, wanted=wanted, packet_filter=packet_filter,
               sequenced=sequenced, stats=stats)
        stats.records_read = reader.records_read
        stats.records_selected = reader.records_selected
    return stats


@dataclass
class PcapExport:
    """What :func:`packets_to_pcap` wrote.

    Attributes:
        records_read: Records in the input.
        records_selected: Of those, records whose ``content_type`` selected
            them as packets.
        packets: Records written to the pcap, one each.
        filtered: Selected records a *packet_filter* left out, including every
            one that is not a whole TCP segment or UDP datagram for it to judge.
        link_type: The pcap's link type.

    """

    records_read: int = 0
    records_selected: int = 0
    packets: int = 0
    filtered: int = 0
    link_type: int = LINKTYPE_RAW

    def summary(self) -> str:
        """Render a short report.

        Returns:
            One line per figure.

        """
        lines = [
            f"input        {self.records_read} records, "
            f"{self.records_selected} selected as packets",
            f"written      {self.packets} packets, link type {self.link_type}",
        ]
        if self.filtered:
            lines.append(f"filtered     {self.filtered}")
        return "\n".join(lines)


def packets_to_pcap(
    source: str | os.PathLike[str] | IO[bytes],
    sink: str | os.PathLike[str] | IO[bytes],
    *,
    content_type: str | None = None,
    link_type: int | None = None,
    packet_filter: Callable[[PacketView], bool] | None = None,
) -> PcapExport:
    """Write the packets of a `.zpf` to a pcap, for Wireshark and the tools that read one.

    An **export for analysis**, not a step in the provenance chain: a pcap
    has nowhere to say which input record a packet came from, so the file
    cites nothing, and :func:`packets_to_zpf` is what keeps the chain.  The
    selection and the order are that function's — the same records, merged
    across the input's streams into timestamp order — but nothing is
    interpreted: each record is written as the bytes it holds, padding
    included, and a fragment as the fragment it is, for the reader to
    reassemble.

    Args:
        source: Path to the input ``.zpf``, binary or JSONL, or an open
            binary stream.
        sink: Path to write, or an open binary stream.
        content_type: The label that makes a record a packet; as for
            :func:`packets_to_zpf`, ``None`` selects ``net:ip`` and
            ``net:ethernet``.
        link_type: The link type of a *content_type* outside ``net:``.
        packet_filter: Called per packet; return ``False`` to exclude it.  It
            sees a record only when the record parses as one whole TCP
            segment or UDP datagram, so with a filter given, fragments and
            records of other protocols are left out.

    Returns:
        What was written.

    Raises:
        ValueError: If the selection is inconsistent, or selects records of
            two link types, which one pcap cannot hold.

    Example:
        >>> export = packets_to_pcap("packets.zpf", "inner.pcap")
        >>> print(export.summary())

    """
    select = _selection(content_type, link_type)
    export = PcapExport()
    with zpf.open(source) as reader:
        streams = [view for session in reader.sessions() for view in session.reassemble()]
        tick_hz = reader.header.tick_hz
        epoch = reader.header.time_epoch or 0
        export.link_type = _one_link_type(streams, select)
        nanoseconds = tick_hz > 1_000_000
        unit = 1_000_000_000 if nanoseconds else 1_000_000

        def records() -> Iterator[tuple[bytes, int, int]]:
            for _index, datagram in _merged(streams):
                export.records_read += 1
                label_link = select.get(datagram.record.content_type or "")
                if label_link is None:
                    continue
                export.records_selected += 1
                if packet_filter is not None and not _passes(datagram, label_link, packet_filter):
                    export.filtered += 1
                    continue
                export.packets += 1
                seconds, rest = divmod(epoch + datagram.ts, tick_hz)
                yield datagram.data, seconds, rest * unit // tick_hz

        where = (
            {"path": sink} if isinstance(sink, (str, os.PathLike)) else {"file_object": sink}
        )
        write_pcap(records(), link_type=export.link_type, nanoseconds=nanoseconds,
                   **where)  # type: ignore[arg-type]
    return export


def _one_link_type(streams: Sequence[_Datagrams], select: Mapping[str, int]) -> int:
    """Return the one link type the selected records share, refusing a mix."""
    kinds = set(select.values())
    if len(kinds) > 1:
        kinds = {
            select[label]
            for stream in streams
            for datagram in stream.datagrams()
            if (label := datagram.record.content_type or "") in select
        }
    if len(kinds) > 1:
        raise ValueError(
            "the selected records are of two link types, which one pcap cannot hold; "
            "pass content_type to export one of them"
        )
    return kinds.pop() if kinds else LINKTYPE_RAW


def _passes(
    datagram: zpf.Datagram, link_type: int, packet_filter: Callable[[PacketView], bool],
) -> bool:
    """Ask *packet_filter* about one record, when it is a packet the filter can judge."""
    packet = parse_packet(datagram.data, link_type=link_type, decode_app=False)
    if skip_reason(packet, headerless=link_type == LINKTYPE_RAW) is not None:
        return False
    view = packet_view(packet, packet_num=0, ts_ticks=datagram.ts, payload_offset=None,
                       fragment_count=1)
    return packet_filter(view)


def _selection(content_type: str | None, link_type: int | None) -> dict[str, int]:
    """Return the labels that make a record a packet, each with the link type it is parsed as."""
    if content_type is None:
        if link_type is not None:
            raise ValueError("a link_type needs a content_type: the net: labels name their own")
        return {f"net:{token}": value for token, value in zpf.NET_LINK_TYPES.items()}
    scheme, _, token = content_type.partition(":")
    if scheme == "net":
        named = zpf.NET_LINK_TYPES.get(token)
        if named is None:
            known = ", ".join(f"net:{t}" for t in zpf.NET_LINK_TYPES)
            raise ValueError(f"{content_type!r} is not a net: label the format defines ({known})")
        if link_type is not None and link_type != named:
            raise ValueError(f"{content_type!r} means link type {named}, not {link_type}")
        return {content_type: named}
    chosen = LINKTYPE_RAW if link_type is None else link_type
    if not supports_link_type(chosen):
        raise ValueError(f"packeteer cannot parse link type {chosen}")
    return {content_type: chosen}


def input_kind(source: str | os.PathLike[str] | IO[bytes]) -> Literal["capture", "zpf"]:
    """Say whether an input is a `.zpf` or a capture.

    The format's own check decides: a ``.zpf`` carries the ``ZIPF`` magic in
    its File Header, or is a JSONL document.  Anything else is taken for a
    capture, which :class:`~zpfwire.capture.CaptureReader` refuses if it is
    not one.

    Args:
        source: A path, or a seekable binary stream (its position is
            restored).

    Returns:
        ``"zpf"`` or ``"capture"``.

    """
    try:
        zpf.detect_face(source)
    except (zpf.ZpfError, ValueError):
        return "capture"
    return "zpf"
