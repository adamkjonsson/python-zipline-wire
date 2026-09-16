"""What the six real Timestamps captures say, phase by phase.

The fixtures are packeteer's ``testcases/real/tcp_*_ts.pcap`` — real Linux
stacks, real loss, duplication, corruption, reordering and a sequence wrap,
every segment carrying the TCP Timestamps option.  Each ``0.3.0`` phase adds
the assertions its rule makes against them; Phase 0 adds only the ones the
tree already satisfies, so that a later phase which breaks one is caught
against a baseline rather than a hope.
"""

from __future__ import annotations

import pathlib

import pytest
from helpers import CAPTURES, to_zpf

from zpfwire import ReassemblyOptions

NO_HOLD = ReassemblyOptions(reorder_window=0)
"""Give up on every hole at once — the policy that makes a receiver-side
capture show its gaps, since the default window absorbs all of them."""


@pytest.mark.parametrize("options", [None, NO_HOLD], ids=["default", "no-hold"])
def test_a_stream_that_wraps_is_placeable(
    tmp_path: pathlib.Path, options: ReassemblyOptions | None,
):
    """``tcp_wrap_ts`` crosses 2**32 mid-stream, and every record still lands.

    The server's ISN sits 36 226 bytes below the wrap, so most of its bytes
    have a sequence number numerically *below* the ``isn`` — under the default
    policy inside one coalesced record that starts just under 2**32 and spans
    it, under ``no-hold`` in records of their own.  The offset space is
    modular and this has always worked; the point of pinning it before Phase
    3 is that the wrap-aware rules are then measured against a file that was
    already right.
    """
    kwargs = {} if options is None else {"options": options}
    out = to_zpf(CAPTURES / "tcp_wrap_ts.pcap", tmp_path, **kwargs)

    assert out.diagnostics == []
    assert out.unplaceable == []
    (session,) = out.sessions
    server = next(p for p in session.participants if p.endpoint.endswith(":8443"))
    assert server.isn == 4294931070
    past_wrap = [
        r for r in session.records
        if r.sender_pid == server.participant_id
        and (r.seq_start < server.isn or r.seq_start + len(r.payload) > 2**32)
    ]
    assert past_wrap, "no record's bytes lie past the wrap"
    # The transfer is 64 KiB.  With no hold, the four delayed pre-wrap
    # originals arrive after their gap was committed and are lost with their
    # resends: 8 × 524 late bytes, of which 4 × 524 were the only copy.
    transferred = 65536 if options is None else 65536 - 4 * 524
    assert len(session.stream(server.participant_id)) == transferred
    assert out.stats.late_bytes == (0 if options is None else 8 * 524)
