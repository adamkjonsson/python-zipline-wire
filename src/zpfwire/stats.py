"""What a conversion did, and what it could not do."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

__all__ = ["ConversionStats"]


@dataclass
class ConversionStats:
    """Tally of one conversion, of a capture or of a ``.zpf`` of packets.

    Everything the input contains is either converted or counted here.  The
    loss-bearing fields — :attr:`skipped`, :attr:`gaps`, :attr:`late_bytes`,
    :attr:`overlap_bytes`, :attr:`duplicate_bytes` — exist so that a
    conversion never drops data silently; a caller is expected to surface
    them.

    Attributes:
        packets: Packets in the capture, including those skipped.
        converted: Packets that reached a session.
        skipped: Tally of why packets were skipped, keyed by
            :class:`~zpfwire.capture.SkipReason`.
        filtered: Packets excluded by a caller-supplied filter.
        sessions: Sessions written.
        records: Records written.
        payload_bytes: Total payload bytes written.
        gaps: Gaps committed — places where a record was emitted past bytes
            that never arrived, after which those bytes may never be written.
        late_bytes: Bytes that arrived after their gap had been committed and
            so had to be dropped.  The total; where the TCP Timestamps option
            can say why they were late, the two fields below split it.
        late_reordered_bytes: Of those, bytes whose TSval was *older* than
            everything committed past their gap — the original transmission,
            delayed by the network.  A wider ``reorder_window`` or a longer
            ``flush_timeout`` would have kept them, so this is the number
            that says the policy was nearly patient enough.
        late_retransmitted_bytes: Of those, bytes whose TSval was *newer* —
            a resend of an original that never arrived, recovered after the
            hole was given up on.  No policy of ours could have kept them; a
            fact about the network.  What remains of :attr:`late_bytes` after
            both is late for a reason the option could not name.
        overlap_bytes: Retransmitted bytes discarded because the same range
            had already been accepted — the sender sent them again, and the
            record covering them says so with ``retransmit``.  A repeat the
            TCP Timestamps option cannot judge lands here too, as the
            conservative reading; :attr:`ts_fallback` says how often.
        duplicates: Segments that were a copy of a transmission already
            accepted — the same packet seen twice by the capture point, as a
            mirror port or a two-interface capture shows it.  The sender
            resent nothing, so no record carries ``retransmit`` on their
            account.  A count of segments rather than bytes because it is a
            statement about the capture: set it beside :attr:`packets` and
            it says how much of the file is doubled.
        duplicate_bytes: Payload bytes those copies carried, all discarded.
        paws_bytes: Payload bytes discarded because the segment's TSval was
            older than the last accepted in order — an old segment from
            before a sequence wrap, which a receiver drops whole (RFC 7323
            §5.3).  Like :attr:`checksum_dropped_bytes` these reached no
            receiver either.
        wrap_resolved: Times a segment that serial arithmetic placed more
            than 2**30 bytes *behind* was recognised as being from ahead,
            because its TSval was newer than the last accepted in order: the
            far side of a hole in the capture too wide for one session to
            span, which without the option would have been miscounted as a
            retransmission and the rest of the direction lost.  Each ends
            the session for ``capture-gap`` — the specification's value for
            the unmeasurable hole, since spec 0.21 — and opens another, so
            each is also a session.
        acked_swaps: Under ``overlap="favor-acked"``, ranges where the copy
            the receiver acknowledged — by the TSecr its ack echoed — was
            not the first copy seen, and replaced it.  Each is a range the
            ``favor-old`` policy would have written wrong.
        acked_fallback_bytes: Under ``favor-acked``, bytes of disagreeing
            copies decided as ``favor-old`` would decide them because the
            evidence never came: no ack covered the run before
            ``flush_timeout`` or ``reorder_window`` was reached, or the ack
            that did carried no Timestamps option, or the session ended
            first.  Non-zero means the file's overlap policy was, for those
            bytes, not the one its Decoder Descriptor names — which is why
            it is counted rather than silent.
        ts_fallback: How often a repeat could not be judged by the Timestamps
            option and was treated as a retransmission, keyed by why —
            :data:`~zpfwire.tcp.TS_ABSENT` when either side lacked the
            option, :data:`~zpfwire.tcp.TS_STALE` when the transmission it
            repeated had aged out of the reassembler's memory.  Non-zero
            means some ``retransmit`` flags in the file rest on the
            specification's conservative reading rather than on evidence.
        undecoded_regions: Undecoded blocks written, each naming a range of
            the capture that reached no record.
        bad_checksum: Packets whose transport checksum did not verify.
            Counted under either policy, so a conversion that kept them still
            says how many there were.
        checksum_dropped_bytes: TCP payload bytes discarded because of a failed
            checksum, which is zero unless the policy is ``"drop"``; a UDP
            datagram is never discarded for one, only counted. Like
            :attr:`filtered` this is a deliberate exclusion rather than a
            loss: the bytes reached no receiver either.
        truncated: Packets that reached a session carrying less than was sent,
            because the capture was taken with a snaplen.  Their payload is
            short, and nothing downstream can tell that from a short payload
            the sender chose — so a non-zero count here is the only warning a
            reader gets.  A TCP stream also shows it as a gap, since the next
            segment's sequence number skips the bytes that were cut; a UDP
            datagram shows it nowhere else at all.
        unlocatable_bytes: Discarded bytes that could not be given an Undecoded
            block because their place in the capture cannot be named — a
            datagram reassembled from several fragments occupies discontiguous
            ranges.  Counted rather than quietly uncited.
        pure_acks: Records written for pure ACKs, under
            :attr:`~zpfwire.options.ReassemblyOptions.pure_acks`.  Included
            in :attr:`records`.
        pure_acks_unstored: Pure ACKs that could not be stored, because they
            arrived behind bytes of their sender's that had already been
            placed, so no stored order puts them where their sequence number
            says.  Their ``ack`` is folded into the sender's next data record
            instead, as it is for every pure ACK when the option is off.
        records_read: Records in the input, when it is a ``.zpf`` of packets
            rather than a capture; ``0`` for a capture.
        records_selected: Of those, records whose ``content_type`` selected
            them as packets.  The rest are not packets, and the stage writing
            the output declares their ranges ``skipped``.

    """

    packets: int = 0
    converted: int = 0
    skipped: Counter[str] = field(default_factory=Counter)
    filtered: int = 0
    sessions: int = 0
    records: int = 0
    payload_bytes: int = 0
    gaps: int = 0
    late_bytes: int = 0
    late_reordered_bytes: int = 0
    late_retransmitted_bytes: int = 0
    overlap_bytes: int = 0
    duplicates: int = 0
    duplicate_bytes: int = 0
    paws_bytes: int = 0
    wrap_resolved: int = 0
    acked_swaps: int = 0
    acked_fallback_bytes: int = 0
    ts_fallback: Counter[str] = field(default_factory=Counter)
    bad_checksum: int = 0
    checksum_dropped_bytes: int = 0
    truncated: int = 0
    undecoded_regions: int = 0
    unlocatable_bytes: int = 0
    pure_acks: int = 0
    pure_acks_unstored: int = 0
    records_read: int = 0
    records_selected: int = 0

    @property
    def lossless(self) -> bool:
        """Report whether every observed stream byte reached the output."""
        return self.gaps == 0 and self.late_bytes == 0

    def summary(self) -> str:
        """Render a short multi-line report.

        Returns:
            One line per figure worth reading, with the loss-bearing ones
            listed only when they are non-zero.

        """
        lines = []
        if self.records_read:
            lines.append(
                f"input        {self.records_read} records, "
                f"{self.records_selected} selected as packets",
            )
        lines += [
            f"packets      {self.packets}",
            f"converted    {self.converted}",
            f"sessions     {self.sessions}",
            f"records      {self.records}"
            + (f" ({self.pure_acks} pure ACKs)" if self.pure_acks else ""),
            f"payload      {self.payload_bytes} bytes",
        ]
        if self.filtered:
            lines.append(f"filtered     {self.filtered}")
        for reason, count in sorted(self.skipped.items()):
            lines.append(f"skipped      {count} ({reason})")
        if self.gaps:
            lines.append(f"gaps         {self.gaps}")
        if self.late_bytes:
            lines.append(f"late bytes   {self.late_bytes} (dropped)")
        if self.late_reordered_bytes:
            lines.append(
                f"  reordered  {self.late_reordered_bytes} "
                "(originals the network delayed; a wider window would have kept them)",
            )
        if self.late_retransmitted_bytes:
            lines.append(
                f"  resent     {self.late_retransmitted_bytes} "
                "(recovered after the gap closed; no policy could have kept them)",
            )
        if self.overlap_bytes:
            lines.append(f"overlap      {self.overlap_bytes} bytes (retransmitted, discarded)")
        if self.duplicates:
            lines.append(
                f"duplicates   {self.duplicates} of {self.packets} packets were copies, "
                f"{self.duplicate_bytes} bytes (discarded)",
            )
        if self.paws_bytes:
            lines.append(f"paws         {self.paws_bytes} bytes rejected (older than the clock)")
        if self.wrap_resolved:
            lines.append(
                f"wrap         {self.wrap_resolved} hole(s) wider than 2^30 bytes; "
                "the session was split there",
            )
        if self.acked_swaps:
            lines.append(
                f"acked        {self.acked_swaps} range(s) took the copy the receiver echoed",
            )
        if self.acked_fallback_bytes:
            lines.append(
                f"acked        {self.acked_fallback_bytes} contested bytes decided as favor-old "
                "(no ack evidence)",
            )
        if self.ts_fallback:
            why = ", ".join(f"{key}: {count}" for key, count in sorted(self.ts_fallback.items()))
            lines.append(
                f"ts fallback  {sum(self.ts_fallback.values())} repeat(s) treated as "
                f"retransmitted without timestamp evidence ({why})",
            )
        if self.bad_checksum:
            lines.append(f"bad cksum    {self.bad_checksum} packet(s)")
        if self.checksum_dropped_bytes:
            lines.append(f"dropped      {self.checksum_dropped_bytes} bytes (bad checksum)")
        if self.truncated:
            lines.append(f"truncated    {self.truncated} packet(s) (payload cut by snaplen)")
        if self.pure_acks_unstored:
            lines.append(
                f"pure ACKs    {self.pure_acks_unstored} not stored (behind their sender's "
                "placed bytes; ack folded instead)",
            )
        if self.undecoded_regions:
            lines.append(f"undecoded    {self.undecoded_regions} region(s) cited")
        if self.unlocatable_bytes:
            lines.append(f"uncited      {self.unlocatable_bytes} bytes (no capture range)")
        return "\n".join(lines)
