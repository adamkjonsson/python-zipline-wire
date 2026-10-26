"""The fidelity tool's truth and ledger (``0.7.0`` Phase 1).

The ledger is the reference every later score is measured against, so these
pin it against what packeteer documents it generates: each impairment alone,
loss with and without recovery, and the self-checks that void a run whose
input is not what the truth claims.  Nothing here converts a capture.
"""

from __future__ import annotations

import dataclasses

import pytest
from fidelity import (
    BLOCK,
    DIRECTIONS,
    PROTOTYPE,
    Impairments,
    Ledger,
    Run,
    Scenario,
    Truth,
    kinds_of,
    run,
    self_check,
)

SEEDS = range(40)
ONE_WAY = (("c2s", 3000), ("c2s", 9000))
"""Data in one direction only: packeteer#227 needs a corruption each way."""

ALONE = {
    "clean": Impairments(),
    "loss": Impairments(packet_loss_probability=0.1),
    "loss-recovered": Impairments(packet_loss_probability=0.1, retransmit_lost=True),
    "retransmission": Impairments(retransmission_probability=0.2),
    "duplication": Impairments(duplicate_probability=0.2),
    "stray": Impairments(stray_packet_count=3),
    "rst": Impairments(server_rst_probability=1.0),
}
"""Every impairment the tree can score today, alone.  Corruption is not here:
under the prototype's two-way shape packeteer#227 voids half its runs."""


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


def test_packeteer_227_voids_the_prototype_s_corruption():
    """Two of the three corrupted segments carry valid checksums.

    The run is evidence about packeteer, not zpfwire: ``checksum="drop"``
    keeps those two, and so does a real receiver.  Not shimmed (Decision 6).
    """
    r = prototype(payload_corruption_probability=0.2)

    assert r.void == (
        "packeteer#227: CORRUPT[1] [5/7] (packet 16) is corrupt and its checksum verifies",
        "packeteer#227: CORRUPT[3] [1/4] (packet 23) is corrupt and its checksum verifies",
    )
    assert len(payload_entries(r, "CORRUPT")) == 3


def test_a_truth_that_is_not_what_was_sent_voids_the_run():
    """One byte more in the first message: every later offset and the FIN disagree."""
    r = prototype()
    shape = ((PROTOTYPE[0][0], PROTOTYPE[0][1] + 1), *PROTOTYPE[1:])
    wrong = Truth.of(dataclasses.replace(r.scenario, shape=shape))

    failures = self_check(wrong, Ledger.of(r.stream, wrong))

    assert any("does not carry the truth" in f for f in failures)
    assert any("FIN-ACK" in f and "not the truth's end 3801" in f for f in failures)
