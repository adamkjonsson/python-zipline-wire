"""TCP fidelity (``0.7.0``, public since ``0.8.0``): truth and ledger, then the scorer.

The truth, ledger, byte score and accounting are ``zpfwire.fidelity``'s; the
order and timing are ``tools/fidelity_tcp.py``'s, and not yet public.

The ledger is the reference every later score is measured against, so the
first half pins it against what packeteer documents it generates: each
impairment alone, loss with and without recovery, and the self-checks that
void a run whose input is not what the truth claims.

The second half converts.  Scores are reported, not asserted (Decision 4),
except where perfection is required — no impairment, duplication with
retransmission, recovered loss — and except the prototype's own numbers,
which are what show the scorer measures what the prototype did.
"""

from __future__ import annotations

import dataclasses

import pytest
import zpf
from fidelity_tcp import dependencies, measure, score_order
from packeteer.generate.tcp import TCP_RST
from packeteer.generate.tcp_stream import TCPStream

from zpfwire import ReassemblyOptions
from zpfwire.fidelity import (
    BLOCK,
    DIRECTIONS,
    PROTOTYPE,
    Impairments,
    Ledger,
    Run,
    Scenario,
    Truth,
    account,
    convert,
    read,
    run,
    score_bytes,
    self_check,
)
from zpfwire.fidelity._common import kinds_of

SEEDS = range(40)
ONE_WAY = (("c2s", 3000), ("c2s", 9000))
"""Data in one direction only: packeteer#227 needs a corruption each way."""

ALONE = {
    "clean": Impairments(),
    "loss": Impairments(packet_loss_probability=0.1),
    "loss-recovered": Impairments(packet_loss_probability=0.1, retransmit_lost=True),
    "retransmission": Impairments(retransmission_probability=0.2),
    "duplication": Impairments(duplicate_probability=0.2),
    "corruption": Impairments(payload_corruption_probability=0.2),
    "stray": Impairments(stray_packet_count=3),
    "rst": Impairments(server_rst_probability=1.0),
}
"""Every impairment, alone.  Corruption joined in packeteer 0.21.0: before
it, packeteer#227 voided half the prototype's corruption runs."""


def prototype(seed: int = 3, **impairments: object) -> Run:
    return run(Scenario(seed=seed, impairments=Impairments(**impairments)))  # type: ignore[arg-type]


def payload_entries(r: Run, kind: str) -> list:
    return [e for e in r.ledger.data() if e.kind == kind]


# ── the truth ───────────────────────────────────────────────────────────


def test_the_truth_is_each_direction_s_messages_concatenated():
    scenario = Scenario()
    truth = Truth.of(scenario)

    assert {d: len(s) for d, s in truth.streams.items()} == {"c2s": 3800, "s2c": 14000}
    messages = scenario.messages()
    for m in truth.messages:
        assert truth.streams[m.direction][m.offset:m.offset + m.length] == messages[m.index].data
    assert [(m.direction, m.offset) for m in truth.messages] == [
        ("c2s", 0), ("s2c", 0), ("c2s", 3000), ("s2c", 9000),
    ]


def test_no_payload_block_repeats():
    """A run written at the wrong offset cannot match the truth there."""
    truth = Truth.of(Scenario())
    blocks = [
        stream[at:at + BLOCK]
        for stream in truth.streams.values()
        for at in range(0, len(stream) - BLOCK + 1, BLOCK)
    ]
    assert len(blocks) == len(set(blocks))


def test_the_truth_does_not_depend_on_the_seed_or_the_impairments():
    a = Truth.of(Scenario(seed=1))
    b = Truth.of(Scenario(seed=2, impairments=Impairments(packet_loss_probability=0.5)))
    assert a == b


def test_a_scenario_reproduces_byte_for_byte():
    """``base_time`` is fixed: packeteer's default is the wall clock."""
    first = Scenario(seed=5, impairments=ALONE["loss-recovered"]).generate()
    again = Scenario(seed=5, impairments=ALONE["loss-recovered"]).generate()
    assert first.to_pcap_tuples() == again.to_pcap_tuples()


# ── labels ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize(("label", "kinds"), [
    ("SYN", ("SYN",)),
    ("FIN-ACK", ("FIN-ACK",)),
    ("DATA[1] [5/7]", ("DATA",)),
    ("RETRANS[1] [5/7]", ("RETRANS",)),
    ("CORRUPT[3]", ("CORRUPT",)),
    ("ACK-RECOVER[0] [2/3]", ("ACK-RECOVER",)),
    ("DUP[3] [1/4]", ("DUP",)),
    ("DUP[CORRUPT[1] [5/7]]", ("DUP", "CORRUPT")),
    ("DUP[RETRANS[2]]", ("DUP", "RETRANS")),
    ("DUP[ACK[2]]", ("DUP", "ACK")),
    ("DUP[RST]", ("DUP", "RST")),
    ("STRAY[0]", ("STRAY",)),
])
def test_a_label_splits_into_its_kinds(label: str, kinds: tuple[str, ...]):
    assert kinds_of(label) == kinds


# ── each impairment alone ───────────────────────────────────────────────


def test_a_clean_stream_carries_the_truth_once():
    r = prototype()
    ledger = r.ledger

    assert r.void == ()
    assert ledger.kinds() == {"SYN": 1, "SYN-ACK": 1, "ACK": 18, "DATA": 15, "FIN-ACK": 2}
    assert all(e.matches and e.checksum_ok for e in ledger.data())
    assert ledger.sent == {"c2s": 3800, "s2c": 14000}
    assert ledger.lost == {"c2s": (), "s2c": ()}
    assert not ledger.reset
    for direction in DIRECTIONS:
        segments = [s for s in ledger.segments if s.direction == direction]
        assert [s.offset for s in segments] == [0] + [s.offset + s.length for s in segments[:-1]]
        assert segments[-1].offset + segments[-1].length == len(r.truth.streams[direction])
    assert all(s.sent_usec == s.first_usec and len(s.copies) == 1 for s in ledger.segments)


def test_loss_without_recovery_leaves_a_hole():
    """The prototype's row: 1,448 s2c bytes, one hole."""
    r = prototype(packet_loss_probability=0.1)

    assert r.void == ()
    assert r.ledger.lost == {"c2s": (), "s2c": ((1448, 2896),)}
    assert r.ledger.sent == {"c2s": 3800, "s2c": 14000}
    assert not any(s.offset == 1448 and s.direction == "s2c" for s in r.ledger.segments)


def test_recovered_loss_is_resent_and_its_original_is_unseen():
    """Loss is drawn while emitting, before recovery: the same segment is lost."""
    r = prototype(packet_loss_probability=0.1, retransmit_lost=True)
    ledger = r.ledger

    assert r.void == ()
    assert ledger.lost == {"c2s": (), "s2c": ()}
    (resent,) = [s for s in ledger.segments if s.sent_usec is None]
    assert (resent.direction, resent.offset, resent.length) == ("s2c", 1448, 1448)
    (copy,) = resent.copies
    assert ledger.entries[copy].kind == "RETRANS" and ledger.entries[copy].matches


def test_a_spurious_retransmission_repeats_the_truth_later():
    r = prototype(retransmission_probability=0.2)
    ledger = r.ledger

    resends = payload_entries(r, "RETRANS")
    assert r.void == () and resends
    for entry in resends:
        assert entry.matches
        (segment,) = [s for s in ledger.segments if entry.index in s.copies]
        assert segment.sent_usec is not None and segment.sent_usec < entry.usec
        assert segment.sent_usec == segment.first_usec


def test_a_duplicate_is_its_original_again():
    """Same TSval, same bytes: the capture point saw one transmission twice."""
    r = prototype(duplicate_probability=0.2)
    ledger = r.ledger

    copies = [e for e in ledger.entries if e.kind == "DUP"]
    assert r.void == () and copies
    for copy in copies:
        (original,) = [
            e for e in ledger.entries
            if e.kind != "DUP" and (e.direction, e.seq, e.flags, e.length, e.tsval)
            == (copy.direction, copy.seq, copy.flags, copy.length, copy.tsval)
            and e.usec < copy.usec
        ]
        assert copy.matches == original.matches


def test_a_stray_is_forged_and_counts_for_nothing():
    """The prototype's three strays: two client-side, one server-side."""
    r = prototype(stray_packet_count=3)
    ledger = r.ledger

    strays = payload_entries(r, "STRAY")
    assert r.void == ()
    assert [(e.direction, e.length) for e in strays] == [("c2s", 348), ("c2s", 350), ("s2c", 71)]
    assert not any(e.matches for e in strays)
    assert not any(e.index in s.copies for e in strays for s in ledger.segments)
    assert ledger.lost == {"c2s": (), "s2c": ()}


def test_a_reset_stops_both_senders():
    r = prototype(server_rst_probability=1.0)
    ledger = r.ledger

    assert r.void == ()
    assert ledger.reset
    assert ledger.kinds()["RST"] == 1
    assert "FIN-ACK" not in ledger.kinds()
    assert ledger.sent == {"c2s": 3000, "s2c": 1448}
    assert ledger.lost == {"c2s": (), "s2c": ()}


def test_corruption_one_way_is_scorable():
    r = run(Scenario(shape=ONE_WAY, seed=3,
                     impairments=Impairments(payload_corruption_probability=0.2)))
    ledger = r.ledger

    corrupt = payload_entries(r, "CORRUPT")
    assert r.void == () and corrupt
    for entry in corrupt:
        assert not entry.checksum_ok and not entry.matches
        (segment,) = [s for s in ledger.segments if entry.index in s.copies]
        assert segment.sent_usec == entry.usec
        assert any(ledger.entries[i].kind == "RETRANS" and ledger.entries[i].matches
                   for i in segment.copies)


@pytest.mark.parametrize("name", ALONE)
def test_no_seed_voids_an_impairment_the_tree_can_score(name: str):
    """Only packeteer#227 voids a run, and only corruption reaches it."""
    for seed in SEEDS:
        r = run(Scenario(seed=seed, impairments=ALONE[name]))
        assert r.void == (), (seed, r.void)


# ── the self-checks ─────────────────────────────────────────────────────


def test_every_corrupted_segment_fails_its_checksum():
    """packeteer#227, fixed in 0.21.0: the prototype's seed 3 is no longer void.

    Under 0.20.0 two of its three corrupted segments carried valid checksums,
    and the run was voided rather than scored (Decision 6).
    """
    r = prototype(payload_corruption_probability=0.2)

    corrupt = payload_entries(r, "CORRUPT")
    assert r.void == ()
    assert len(corrupt) == 3
    assert not any(e.checksum_ok for e in corrupt)


def test_a_corrupted_segment_with_a_valid_checksum_voids_the_run():
    """The packeteer#227 check stays: a regression there must void, not score."""
    r = prototype(payload_corruption_probability=0.2)
    entries = tuple(
        dataclasses.replace(e, checksum_ok=True) if e.label == "CORRUPT[1] [5/7]" else e
        for e in r.ledger.entries
    )

    failures = self_check(r.truth, dataclasses.replace(r.ledger, entries=entries))

    assert failures == [
        "packeteer#227: CORRUPT[1] [5/7] (packet 16) is corrupt and its checksum verifies",
    ]


def test_a_truth_that_is_not_what_was_sent_voids_the_run():
    """One byte more in the first message: every later offset and the FIN disagree."""
    r = prototype()
    shape = ((PROTOTYPE[0][0], PROTOTYPE[0][1] + 1), *PROTOTYPE[1:])
    wrong = Truth.of(dataclasses.replace(r.scenario, shape=shape))

    failures = self_check(wrong, Ledger.of(r.stream, wrong))

    assert any("does not carry the truth" in f for f in failures)
    assert any("FIN-ACK" in f and "not the truth's end 3801" in f for f in failures)


# ── the byte scorer ─────────────────────────────────────────────────────

PERFECT = {
    "clean": Impairments(),
    "duplication-and-retransmission": Impairments(
        duplicate_probability=0.2, retransmission_probability=0.2,
    ),
    "loss-recovered": Impairments(packet_loss_probability=0.1, retransmit_lost=True),
}
"""Where perfection is required: nothing was destroyed, and nothing ambiguous."""

POLICIES = {
    "favor-old": ReassemblyOptions(),
    "favor-acked": ReassemblyOptions(overlap="favor-acked"),
    "checksum-drop": ReassemblyOptions(checksum="drop"),
}


@pytest.mark.parametrize("name", PERFECT)
def test_what_must_be_perfect_is(name: str):
    """Fidelity 1 and recovery 1 over 40 seeds, and the file's account of itself holds."""
    for seed in SEEDS:
        r = run(Scenario(seed=seed, impairments=PERFECT[name]))
        m = measure(r)

        assert r.void == (), seed
        assert m.total.fidelity == 1.0 and m.total.recovery == 1.0, (seed, m.bytes)
        assert m.total.causes == {} and m.total.extra == 0, seed
        assert m.accounting.failures(late_bytes=m.conversion.stats.late_bytes) == [], seed


@pytest.mark.parametrize("policy", POLICIES)
def test_the_prototype_s_corruption_row(policy: str):
    """1 c2s + 2 s2c wrong by default, none under ``favor-acked`` or dropping.

    Under packeteer 0.20.0 the run was void (packeteer#227), and
    ``checksum="drop"`` kept two s2c bytes: the two corrupted copies whose
    checksums verified.  Since 0.21.0 every corrupted copy fails its
    checksum, so dropping keeps none.
    """
    r = prototype(payload_corruption_probability=0.2)
    m = measure(r, POLICIES[policy])

    expected = {"favor-old": (1, 2), "favor-acked": (0, 0), "checksum-drop": (0, 0)}[policy]
    assert r.void == ()
    assert (m.bytes["c2s"].substituted, m.bytes["s2c"].substituted) == expected
    assert m.total.causes == ({"substituted:corrupt": sum(expected)} if sum(expected) else {})
    assert m.total.missing_declared == m.total.missing_past_end == 0


@pytest.mark.parametrize("policy", POLICIES)
def test_the_prototype_s_stray_row(policy: str):
    """Strays win under every policy: the first forgery arrives first.

    ``STRAY[0]``'s 348 bytes and the last 2 of ``STRAY[1]``'s 350, at the
    same offset, are written before the real segment arrives.  Two of the
    350 equal the truth by chance — one in 256 — so 348 are wrong.  The
    prototype counted 349 over different payloads.
    """
    m = measure(prototype(stray_packet_count=3), POLICIES[policy])

    assert m.bytes["c2s"].substituted == 348
    assert m.bytes["c2s"].correct == 3800 - 348
    assert m.total.causes == {"substituted:stray": 348}
    assert m.bytes["c2s"].available == 3800
    assert m.total.recovery == m.total.fidelity


def test_lost_bytes_lower_fidelity_and_leave_recovery_alone():
    m = measure(prototype(packet_loss_probability=0.1))

    assert m.bytes["s2c"].missing_declared == 1448
    assert m.total.causes == {"missing:lost": 1448}
    assert m.total.recovery == 1.0
    assert m.total.fidelity == (17800 - 1448) / 17800
    assert m.accounting.gaps == m.accounting.gaps_in_file == m.accounting.holes == 1


def test_a_lost_tail_is_missing_past_the_end():
    """``chunks()`` yields no trailing Gap: only the truth can see this."""
    tail = next(
        r for seed in SEEDS
        if (r := run(Scenario(seed=seed, impairments=Impairments(packet_loss_probability=0.1))))
        and any(stop == r.ledger.sent[d] for d in DIRECTIONS for _, stop in r.ledger.lost[d])
    )
    m = measure(tail)

    assert m.total.missing_past_end > 0
    assert m.total.causes["missing:lost"] == m.total.missing_declared + m.total.missing_past_end


def test_copies_are_judged_copies():
    """Duplication alone: every repeat is a copy of one transmission, and is cited so."""
    for seed in range(10):
        a = measure(run(Scenario(seed=seed, impairments=Impairments(duplicate_probability=0.3))))
        a = a.accounting
        assert a.copies_as_resends == 0 and a.resends_as_copies == 0, seed
        assert set(a.judged) <= {("copy", "duplicate-discarded")}, seed


# ── shown to fail ───────────────────────────────────────────────────────


def test_an_output_one_byte_off_scores_nothing():
    """Position-unique payloads: a stream written one offset late matches by chance only."""
    r = prototype()
    output = convert(r.stream).output
    # As chunks() would yield it: a leading Gap before the first byte.
    shifted = {
        d: (zpf.Gap(0, 1), *(
            zpf.Segment(c.data, c.off_start + 1, c.off_end + 1, c.ts)
            for c in output.chunks[d]
        ))
        for d in DIRECTIONS
    }
    late = dataclasses.replace(output, chunks=shifted)

    for direction in DIRECTIONS:
        score = score_bytes(r, late, direction)
        assert score.fidelity < 0.01
        assert score.missing_declared == 1 and score.extra == 1


def test_a_missing_citation_is_bytes_lost_quietly():
    r = prototype(duplicate_probability=0.2)
    conversion = convert(r.stream)
    start, stop, _ = conversion.output.undecoded[0]
    output = dataclasses.replace(conversion.output, undecoded=conversion.output.undecoded[1:])

    accounting = account(r, dataclasses.replace(conversion, output=output))

    assert account(r, conversion).failures() == []
    assert accounting.quiet == stop - start
    assert accounting.failures() == [
        f"{stop - start} captured bytes reached no record and no citation",
    ]


def test_a_reset_the_file_does_not_show_is_reported():
    """The ledger saw an RST; a capture without it ends the session otherwise."""
    r = prototype(server_rst_probability=1.0)
    unreset = TCPStream([p for p in r.stream.packets if not p.flags & TCP_RST])
    # Citations are located in the converted stream, so the ledger is
    # rebuilt from it — and told of the reset the capture no longer shows.
    ledger = dataclasses.replace(Ledger.of(unreset, r.truth), reset=True)
    conversion = convert(unreset)
    accounting = account(dataclasses.replace(r, stream=unreset, ledger=ledger), conversion)

    assert accounting.expected_end == "rst"
    assert accounting.end_reason != "rst"
    assert f"the session ends {accounting.end_reason!r}, not 'rst'" in accounting.failures()


# ── order and timing ────────────────────────────────────────────────────

PUSHED = 1.0
"""PSH on every message, as a real stack sets it at the end of each write."""

ORDERED = {
    **ALONE,
    "duplication-and-retransmission": PERFECT["duplication-and-retransmission"],
}


@pytest.mark.parametrize("sequenced", [False, True], ids=["merge", "sequenced"])
@pytest.mark.parametrize("name", ORDERED)
def test_pushed_messages_keep_their_causal_order(name: str, sequenced: bool):
    """No message is placed before one it depends on, on either path.

    A stray can still put a message's first byte early — the byte is the
    forgery's, and is counted as forged — and a recovered loss can still put
    a reply before the request it was sent without acknowledging.
    """
    for seed in SEEDS:
        r = run(Scenario(seed=seed, impairments=ORDERED[name], psh_probability=PUSHED))
        order = measure(r, sequenced=sequenced).order
        assert order.inversions == 0, (seed, order.positions)


@pytest.mark.parametrize("sequenced", [False, True], ids=["merge", "sequenced"])
@pytest.mark.parametrize("name", ORDERED)
def test_unpushed_messages_keep_their_causal_order(name: str, sequenced: bool):
    """At packeteer's PSH rate, half the messages end without PSH, and order holds anyway.

    Until #55 a run ended only at PSH, so an unpushed request's run took in
    the next request too, after the response had answered it: a record
    holding bytes from both sides of the response, which no position could
    place.  In 35 of 40 clean runs the response came before its request.
    A run now ends where peer data answers it.  Strays are converted with
    ``require_timestamps`` (#57): a forged segment's ack is a forgery too,
    and drained into a real record it misplaces it.
    """
    options = ReassemblyOptions(require_timestamps=True) if name == "stray" else None
    for seed in SEEDS:
        r = run(Scenario(seed=seed, impairments=ORDERED[name]))
        order = measure(r, options, sequenced=sequenced).order
        assert order.inversions == 0, (seed, order.positions)


def test_a_reply_sent_into_a_loss_does_not_depend_on_the_request():
    """Seed 1: the request's first segment is lost, and the reply goes out anyway.

    The reply acknowledges nothing of the request, so placing it first is
    reordering, not a failure.
    """
    r = run(Scenario(seed=1, impairments=ALONE["loss-recovered"], psh_probability=PUSHED))
    order = measure(r).order

    assert 0 not in dependencies(r)[1]
    assert order.positions[1] < order.positions[0]
    assert order.reordered == 1 and order.inversions == 0


def test_a_message_that_starts_its_record_is_dated_exactly_by_ts_first():
    """``timestamp`` is when a record completed; ``ts_first`` when it began."""
    order = measure(run(Scenario(seed=3, psh_probability=PUSHED))).order

    assert all(t.starts_record and t.correct for t in order.timing)
    assert [t.ts_first_error for t in order.timing] == [0, 0, None, 0]
    assert [t.timestamp_error for t in order.timing] == [4000, 12000, 0, 6000]


def test_a_recovered_loss_is_late_by_the_retransmission_timeout():
    rto = 200_000
    recovered = [
        t for seed in SEEDS
        for t in measure(run(Scenario(seed=seed, impairments=ALONE["loss-recovered"],
                                      psh_probability=PUSHED))).order.timing
        if t.recovered
    ]

    assert recovered
    assert all(rto <= t.timestamp_error <= rto + 20_000 for t in recovered)


def test_a_hand_reordered_file_reports_its_inversion():
    """The reader trusts a sequenced session's stored order: only the scorer can object.

    Swapping the first response's record with the second request's moves the
    request ahead of the response it acknowledges.  Each participant's own
    records stay in order, so the file still reads clean.
    """
    r = run(Scenario(seed=3, psh_probability=PUSHED))
    conversion = convert(r.stream, ReassemblyOptions(pure_acks=False), sequenced=True,
                         face="jsonl")
    lines = conversion.data.decode().splitlines(keepends=True)
    records = [i for i, line in enumerate(lines) if line.startswith('{"type":"record"')]
    # SYN, SYN-ACK, then one record per message: swap messages 1 and 2.
    a, b = records[3], records[4]
    lines[a], lines[b] = lines[b], lines[a]
    reordered = read("".join(lines).encode())

    assert score_order(r, conversion.output).inversions == 0
    order = score_order(r, reordered)
    assert order.positions == (0, 2, 1, 3)
    assert order.inversions == 1


def test_a_resend_s_ack_is_not_its_message_s():
    """Message 124's original is lost; its resend acknowledges a reply sent after it.

    Taken from the resend, the ack would make 124 — and every later client
    message — depend on reply 121, and a file that rightly places them
    before it would score an inversion.
    """
    shape = (("c2s", 64), ("s2c", 256)) * 100
    r = run(Scenario(shape=shape, seed=2, psh_probability=PUSHED,
                     impairments=ALONE["loss-recovered"]))

    deps = dependencies(r)
    assert 121 not in deps[124] and 121 not in deps[126]
    assert 120 in deps[124]  # its own direction
