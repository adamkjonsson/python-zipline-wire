"""What a conversion did, and what it could not do."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

__all__ = ["ConversionStats"]


@dataclass
class ConversionStats:
    """Tally of one capture conversion.

    Everything a capture contains is either converted or counted here.  The
    loss-bearing fields — :attr:`skipped`, :attr:`gaps`, :attr:`late_bytes`,
    :attr:`overlap_bytes` — exist so that a conversion never drops data
    silently; a caller is expected to surface them.

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
            so had to be dropped.
        overlap_bytes: Retransmitted bytes discarded because the same range
            had already been accepted.

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
    overlap_bytes: int = 0

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
        lines = [
            f"packets      {self.packets}",
            f"converted    {self.converted}",
            f"sessions     {self.sessions}",
            f"records      {self.records}",
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
        if self.overlap_bytes:
            lines.append(f"overlap      {self.overlap_bytes} bytes (discarded)")
        return "\n".join(lines)
