"""Measure how well a conversion represents the traffic that was actually sent.

packeteer generates a TCP conversation under impairments of the caller's
choosing — loss, retransmission, duplication, corruption, forged segments, a
reset — and knows exactly what each application sent and what happened to
every packet.  zpfwire converts the impaired capture, and this package scores
the ``.zpf`` against what was sent.  The point is to choose a reassembly
policy — ``overlap``, ``reorder_window``, ``acked_hold`` — for a link from
evidence rather than defaults.

Describe a conversation with a :class:`Scenario`, and either measure one
seed of it::

    from zpfwire.fidelity import Impairments, Scenario, measure, run

    r = run(Scenario(seed=3, impairments=Impairments(packet_loss_probability=0.1)))
    m = measure(r)
    m.total.fidelity, m.accounting.failures()

or evaluate a policy over many seeds, as ``zpfwire fidelity`` does::

    from zpfwire import ReassemblyOptions
    from zpfwire.fidelity import evaluate

    e = evaluate(scenario, ReassemblyOptions(overlap="favor-acked"), seeds=range(40))
    print(e.report())

What is promised, since ``0.8.0`` (#63): the scenario, the truth and the
ledger; the byte score — *fidelity* against what was sent, *recovery*
against what was captured, every wrong byte attributed to its cause; and
the accounting, whether the file and its stats tell the truth about
themselves.  Not yet: the order and timing of messages, whose definitions
are still settling, and UDP.  Both are measured by the project's own tool,
``tools/fidelity.py``, without a promise.

This package imports packeteer's generators, which an ordinary conversion
never needs, so ``import zpfwire`` does not import it.
"""

from __future__ import annotations

from zpfwire.fidelity._common import (
    BASE_TIME,
    BLOCK,
    CLIENT,
    DIRECTIONS,
    Direction,
    Unclean,
    payload,
)
from zpfwire.fidelity._evaluate import Evaluation, Outcome, evaluate, parse_shape
from zpfwire.fidelity._tcp import (
    PROTOTYPE,
    Accounting,
    ByteScore,
    Conversion,
    Entry,
    Impairments,
    Ledger,
    Measurement,
    Message,
    Output,
    Run,
    Scenario,
    Segment,
    Truth,
    account,
    convert,
    measure,
    read,
    run,
    score_bytes,
    self_check,
)

__all__ = [
    "BASE_TIME",
    "BLOCK",
    "CLIENT",
    "DIRECTIONS",
    "PROTOTYPE",
    "Accounting",
    "ByteScore",
    "Conversion",
    "Direction",
    "Entry",
    "Evaluation",
    "Impairments",
    "Ledger",
    "Measurement",
    "Message",
    "Outcome",
    "Output",
    "Run",
    "Scenario",
    "Segment",
    "Truth",
    "Unclean",
    "account",
    "convert",
    "evaluate",
    "measure",
    "parse_shape",
    "payload",
    "read",
    "run",
    "score_bytes",
    "self_check",
]
