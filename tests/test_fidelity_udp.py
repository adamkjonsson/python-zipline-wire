"""The fidelity tool's UDP half (``0.8.0``, #64): the truth and the ledger.

The ledger is the reference every later score is measured against, so it is
pinned against what packeteer documents it generates: each impairment alone,
all of them at once, fragmentation, and the self-checks that void a run
whose input is not what the truth claims.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable

import pytest
from fidelity_udp import (
    GAP_USEC,
    PATHS,
    PROTOTYPE,
    Accounting,
    Conversion,
    Delivery,
    Impairments,
    Ledger,
    OrderScore,
    Run,
    Scenario,
    Truth,
    Written,
    measure,
    run,
    score,
    self_check,
)
from packeteer.parse import parse_packet

from zpfwire import ReassemblyOptions
from zpfwire.fidelity import BASE_TIME, BLOCK

SEEDS = range(40)

ALONE = {
    "clean": Impairments(),
    "loss": Impairments(packet_loss_probability=0.1),
    "duplication": Impairments(duplicate_probability=0.2),
    "reorder": Impairments(reorder_probability=0.2),
    "corruption": Impairments(payload_corruption_probability=0.2),
}
"""Every impairment packeteer applies to a datagram, alone."""

ALL = Impairments(
    packet_loss_probability=0.1, payload_corruption_probability=0.2,
    reorder_probability=0.2, duplicate_probability=0.2,
)

FRAGMENTING = 576
"""An MTU most of :data:`PROTOTYPE`'s datagrams exceed."""


def prototype(seed: int = 3, mtu: int | None = None, **impairments: object) -> Run:
    return run(Scenario(seed=seed, mtu=mtu,
                        impairments=Impairments(**impairments)))  # type: ignore[arg-type]


# ── the truth ───────────────────────────────────────────────────────────


def test_the_truth_is_each_datagram_in_send_order():
    scenario = Scenario()
    truth = Truth.of(scenario)

    assert [(d.direction, len(d.data)) for d in truth.datagrams] == list(PROTOTYPE)
    assert [d.data for d in truth.datagrams] == [m.data for m in scenario.messages()]
    assert [d.sent_usec for d in truth.datagrams] == [
        BASE_TIME * 1_000_000 + (i + 1) * GAP_USEC for i in range(len(PROTOTYPE))
    ]


def test_each_datagram_s_first_block_is_its_own():
    """A record is traced to its datagram by its first block, even when its last byte is corrupt."""
    firsts = [d.data[:BLOCK] for d in Truth.of(Scenario()).datagrams]
    assert len(firsts) == len(set(firsts))


def test_the_truth_does_not_depend_on_the_seed_the_impairments_or_the_mtu():
    a = Truth.of(Scenario(seed=1))
    b = Truth.of(Scenario(seed=2, impairments=ALL, mtu=FRAGMENTING))
    assert a == b


@pytest.mark.parametrize("mtu", [
    None,
    pytest.param(FRAGMENTING, marks=pytest.mark.xfail(
        strict=True,
        reason="packeteer#232: a fragmented datagram's IP ID is drawn from the unseeded "
               "global random, since the generator builds every datagram with ID 0",
    )),
], ids=["whole", "fragmented"])
def test_a_scenario_reproduces_byte_for_byte(mtu: int | None):
    """``base_time`` is fixed: packeteer's default is the wall clock."""
    first = Scenario(seed=5, impairments=ALL, mtu=mtu).generate()
    again = Scenario(seed=5, impairments=ALL, mtu=mtu).generate()
    assert first.to_pcap_tuples() == again.to_pcap_tuples()


# ── each impairment alone ───────────────────────────────────────────────


def test_a_clean_flow_carries_each_datagram_once():
    r = prototype()

    assert r.void == ()
    assert r.ledger.kinds() == {"DATA": len(PROTOTYPE)}
    assert r.ledger.lost == ()
    assert [c.datagram for c in r.ledger.copies] == list(range(len(PROTOTYPE)))
    assert all(c.payload == d.data and c.checksum_ok
               for c, d in zip(r.ledger.copies, r.truth.datagrams, strict=True))
    assert set(r.ledger.overtaken) == {0}


@pytest.mark.parametrize("seed", SEEDS)
def test_a_lost_datagram_has_no_copy(seed: int):
    r = prototype(seed, **dataclasses.asdict(ALONE["loss"]))

    carried = {c.datagram for c in r.ledger.copies}
    assert r.void == ()
    assert set(r.ledger.lost) == set(range(len(PROTOTYPE))) - carried
    assert r.ledger.kinds() == {"DATA": len(PROTOTYPE) - len(r.ledger.lost)}


@pytest.mark.parametrize("seed", SEEDS)
def test_a_duplicate_is_the_same_datagram_a_little_later(seed: int):
    r = prototype(seed, **dataclasses.asdict(ALONE["duplication"]))

    assert r.void == ()
    assert r.ledger.lost == ()
    for copy in r.ledger.copies:
        if copy.kind == "DUP":
            original, again = r.ledger.of_datagram(copy.datagram)
            assert again is copy
            assert (original.payload, original.checksum_ok) == (copy.payload, copy.checksum_ok)
            assert copy.usec > original.usec


@pytest.mark.parametrize("seed", SEEDS)
def test_only_a_reordered_datagram_is_overtaken(seed: int):
    """A reordered datagram is held back behind later ones going its own way.

    Not by at most ``reorder_depth``: only a datagram delivered in its turn
    counts toward the wait, so one released from its own hold first
    overtakes it as well.
    """
    r = prototype(seed, **dataclasses.asdict(ALONE["reorder"]))

    assert r.void == ()
    for copy, overtaken in zip(r.ledger.copies, r.ledger.overtaken, strict=True):
        if copy.kind == "REORDER":
            assert overtaken >= 1
        else:
            assert copy.kind == "DATA"
            assert overtaken == 0


@pytest.mark.parametrize("seed", SEEDS)
def test_a_corrupted_datagram_fails_its_checksum_and_differs_in_its_last_byte(seed: int):
    r = prototype(seed, **dataclasses.asdict(ALONE["corruption"]))

    assert r.void == ()
    for copy in r.ledger.copies:
        sent = r.truth.datagrams[copy.datagram].data
        assert copy.checksum_ok is not copy.corrupt
        assert copy.payload[:-1] == sent[:-1]
        assert (copy.payload[-1] != sent[-1]) is copy.corrupt


@pytest.mark.parametrize("seed", SEEDS)
@pytest.mark.parametrize("mtu", [None, FRAGMENTING], ids=["whole", "fragmented"])
def test_every_impairment_at_once_voids_nothing(seed: int, mtu: int | None):
    r = prototype(seed, mtu, **dataclasses.asdict(ALL))

    assert r.void == ()
    carried = {c.datagram for c in r.ledger.copies}
    assert carried | set(r.ledger.lost) == set(range(len(PROTOTYPE)))


def test_the_checksum_agrees_with_packeteer_where_packeteer_can_verify_it():
    """A parsed checksum is kept only where it does not verify (packeteer#68).

    It cannot verify a fragment's, which is why the ledger computes its own.
    """
    r = prototype(**dataclasses.asdict(ALL))
    for copy in r.ledger.copies:
        (index,) = copy.packets
        parsed = parse_packet(r.stream.packets[index].raw, decode_app=False)
        assert parsed.transport is not None
        assert copy.checksum_ok is (parsed.transport.checksum is None)


# ── fragmentation ───────────────────────────────────────────────────────


@pytest.mark.parametrize("seed", SEEDS)
def test_a_fragmented_datagram_is_one_copy(seed: int):
    r = prototype(seed, FRAGMENTING, **dataclasses.asdict(ALONE["duplication"]))

    assert r.void == ()
    frames = sorted(i for c in r.ledger.copies for i in c.packets)
    assert frames == list(range(len(r.stream.packets)))
    for copy in r.ledger.copies:
        sent = r.truth.datagrams[copy.datagram]
        assert copy.payload == sent.data
        # 20 bytes of IPv4 header and 8 of UDP.
        assert copy.fragmented is (len(sent.data) + 28 > FRAGMENTING)
        assert copy.usec - copy.first_usec >= len(copy.packets) - 1


@pytest.mark.parametrize("mtu", [None, FRAGMENTING], ids=["whole", "fragmented"])
def test_a_copy_s_pieces_are_its_payload_in_the_frames(mtu: int | None):
    """What a citation into the capture is located by, in Phase 4."""
    r = prototype(mtu=mtu, **dataclasses.asdict(ALL))
    for copy in r.ledger.copies:
        rebuilt = bytearray(len(copy.payload))
        for piece in copy.pieces:
            frame = r.stream.packets[piece.packet].raw[piece.at:piece.at + piece.length]
            rebuilt[piece.offset:piece.offset + piece.length] = frame
        assert sum(p.length for p in copy.pieces) == len(copy.payload)
        assert bytes(rebuilt) == copy.payload


def test_an_empty_datagram_is_a_copy_and_its_corruption_is_its_checksum():
    """A corrupted empty datagram has its checksum's last byte flipped: no payload changes."""
    shape = (("c2s", 0), ("s2c", 0), ("c2s", 0), ("s2c", 0))
    for seed in SEEDS:
        r = run(Scenario(shape=shape, seed=seed,
                         impairments=Impairments(payload_corruption_probability=0.5)))
        assert r.void == ()
        assert [c.payload for c in r.ledger.copies] == [b""] * 4
        assert all(c.pieces == () for c in r.ledger.copies)


# ── the self-checks ─────────────────────────────────────────────────────


def _damaged(r: Run, label: str, **change: object) -> Ledger:
    copies = tuple(
        dataclasses.replace(c, **change) if c.label == label else c  # type: ignore[arg-type]
        for c in r.ledger.copies
    )
    return dataclasses.replace(r.ledger, copies=copies)


def test_a_corrupted_datagram_whose_checksum_verifies_voids_the_run():
    """packeteer#227's shape, for UDP: nothing could tell the corruption apart."""
    r = prototype(**dataclasses.asdict(ALONE["corruption"]))
    corrupt = next(c for c in r.ledger.copies if c.corrupt)

    failures = self_check(r.truth, _damaged(r, corrupt.label, checksum_ok=True))
    assert failures == [f"{corrupt.label} is corrupt, and its checksum verifies"]


def test_a_duplicate_that_differs_voids_the_run():
    r = prototype(**dataclasses.asdict(ALONE["duplication"]))
    dup = next(c for c in r.ledger.copies if c.kind == "DUP")
    forged = dup.payload[:-1] + bytes([dup.payload[-1] ^ 1])

    failures = self_check(r.truth, _damaged(r, dup.label, payload=forged))
    assert f"{dup.label} does not carry its datagram's bytes" in failures
    assert any(f.startswith(f"{dup.label} differs from ") for f in failures)


def test_a_datagram_not_carrying_the_truth_voids_the_run():
    r = prototype()
    first = r.ledger.copies[0]

    failures = self_check(r.truth, _damaged(r, first.label, payload=first.payload[1:]))
    assert failures == [f"{first.label} does not carry its datagram's bytes"]


def test_a_datagram_captured_off_its_send_time_voids_the_run():
    r = prototype()
    first = r.ledger.copies[0]

    failures = self_check(r.truth, _damaged(r, first.label, first_usec=first.first_usec + 1))
    assert len(failures) == 1 and "not its send time" in failures[0]


# ── the scorer ──────────────────────────────────────────────────────────


@pytest.mark.parametrize("seed", SEEDS)
@pytest.mark.parametrize("impairment", sorted(ALONE))
@pytest.mark.parametrize("path", PATHS)
def test_every_captured_datagram_is_written_as_captured(seed: int, impairment: str, path: str):
    """The one place a UDP score is asserted (``0.7.0`` Decision 4).

    zpfwire makes no choice about a whole datagram, and the specification
    forbids it to withhold one: every captured copy, a duplicate's and a
    corrupt one's included, reaches exactly one record, in capture order,
    stamped with its capture time.
    """
    r = prototype(seed, **dataclasses.asdict(ALONE[impairment]))
    m = measure(r, path=path)  # type: ignore[arg-type]

    assert m.accounting.failures() == []
    assert m.delivery.conservation == 1
    assert m.delivery.withheld == m.delivery.cited == 0
    assert m.order.unexplained == 0


@pytest.mark.parametrize("seed", range(10))
def test_checksum_drop_keeps_a_corrupt_datagram(seed: int):
    """``checksum="drop"`` is TCP's only: a UDP datagram left out would leave no trace (0.5.0)."""
    r = prototype(seed, **dataclasses.asdict(ALONE["corruption"]))
    m = measure(r, ReassemblyOptions(checksum="drop"))

    assert m.accounting.failures() == []
    assert m.delivery.conservation == 1
    assert m.delivery.altered == sum(1 for c in r.ledger.copies if c.corrupt)


@pytest.mark.parametrize("seed", range(10))
def test_the_packets_path_withholds_a_fragmented_datagram_and_cites_it(seed: int):
    """zipline#166: no record without ``seq_start`` may cite several input records."""
    r = prototype(seed, FRAGMENTING, **dataclasses.asdict(ALL))
    m = measure(r, path="packets")

    fragmented = sum(1 for c in r.ledger.copies if c.fragmented)
    assert fragmented
    assert m.accounting.failures() == []
    assert m.delivery.cited == fragmented
    assert m.delivery.written == len(r.ledger.copies) - fragmented
    # The capture path writes them all.
    assert measure(r).delivery.conservation == 1


def test_a_fragmented_datagram_is_stamped_with_its_last_fragment():
    """Pinned: the record is complete when its last fragment is, so its time is that one's."""
    r = prototype(mtu=FRAGMENTING)
    m = measure(r)

    fragmented = [t for t in m.order.timing if r.ledger.of_datagram(t.datagram)[0].fragmented]
    assert fragmented
    assert all(t.error_usec >= 1 for t in fragmented)
    assert m.accounting.mistimed == 0


def test_a_reordered_datagram_is_stored_where_it_arrived():
    """A stream with no sequence numbers is stored in capture order (the spec's rule).

    Every inversion of send order is the network's, and the ledger explains
    each by the datagram it shows held back.
    """
    r = prototype(**dataclasses.asdict(ALONE["reorder"]))
    m = measure(r)

    assert m.order.inversions > 0
    assert m.order.unexplained == 0
    assert m.accounting.misordered == 0


# ── shown to fail ───────────────────────────────────────────────────────


def _rescored(
    r: Run, conversion: Conversion, **output: object,
) -> tuple[Delivery, Accounting, OrderScore]:
    """Score *conversion* with parts of its output replaced, as a broken converter would."""
    broken = dataclasses.replace(conversion.output, **output)  # type: ignore[arg-type]
    return score(r, dataclasses.replace(conversion, output=broken))


def _records(
    conversion: Conversion, direction: str, change: Callable[[list[Written]], list[Written]],
) -> dict[str, object]:
    records = dict(conversion.output.records)
    records[direction] = tuple(change(list(records[direction])))
    timeline = tuple((d, w) for d in ("c2s", "s2c") for w in records[d])
    return {"records": records, "timeline": tuple(sorted(timeline, key=lambda t: t[1].usec))}


@pytest.fixture
def lossless() -> tuple[Run, Conversion]:
    r = prototype(**dataclasses.asdict(ALONE["duplication"]))
    return r, measure(r).conversion


def test_a_record_removed_is_a_datagram_lost_quietly(lossless: tuple[Run, Conversion]):
    r, conversion = lossless
    delivery, accounting, _ = _rescored(r, conversion, **_records(
        conversion, "c2s", lambda rs: rs[:3] + rs[4:]))

    assert delivery.conservation < 1
    assert accounting.quiet == 1
    assert "1 captured copies reached no record and no citation" in accounting.failures()


def test_a_record_written_twice_is_invented(lossless: tuple[Run, Conversion]):
    r, conversion = lossless
    _, accounting, _ = _rescored(r, conversion, **_records(
        conversion, "s2c", lambda rs: rs[:3] + [rs[2]] + rs[3:]))

    assert accounting.invented == 1


def test_a_record_with_other_bytes_matches_no_copy(lossless: tuple[Run, Conversion]):
    r, conversion = lossless

    def alter(rs: list[Written]) -> list[Written]:
        rs[5] = dataclasses.replace(rs[5], payload=rs[5].payload[::-1])
        return rs

    _, accounting, _ = _rescored(r, conversion, **_records(conversion, "c2s", alter))
    assert accounting.unknown == 1 and accounting.quiet == 1


def test_two_records_swapped_are_an_unexplained_inversion(lossless: tuple[Run, Conversion]):
    r, conversion = lossless

    def swap(rs: list[Written]) -> list[Written]:
        rs[6], rs[7] = rs[7], rs[6]
        return rs

    _, accounting, order = _rescored(r, conversion, **_records(conversion, "s2c", swap))
    assert accounting.misordered == 1
    assert order.unexplained == 1


def test_a_timestamp_moved_by_a_microsecond_is_caught(lossless: tuple[Run, Conversion]):
    r, conversion = lossless

    def shift(rs: list[Written]) -> list[Written]:
        rs[0] = dataclasses.replace(rs[0], usec=rs[0].usec + 1)
        return rs

    _, accounting, _ = _rescored(r, conversion, **_records(conversion, "c2s", shift))
    assert accounting.mistimed == 1


def test_a_citation_removed_is_a_datagram_lost_quietly():
    r = prototype(mtu=FRAGMENTING)
    conversion = measure(r, path="packets").conversion
    _, accounting, _ = _rescored(r, conversion, undecoded=conversion.output.undecoded[1:])

    # The first fragmented datagram's first fragment is now uncited.
    assert accounting.partial == 1


def test_a_span_naming_the_wrong_frame_is_misattributed():
    r = prototype()
    conversion = measure(r, path="packets").conversion

    def misname(rs: list[Written]) -> list[Written]:
        (space, start, end), = rs[1].spans
        rs[1] = dataclasses.replace(rs[1], spans=((space, start + 1, end + 1),))
        return rs

    _, accounting, _ = _rescored(r, conversion, **_records(conversion, "c2s", misname))
    assert accounting.misattributed == 1


@pytest.mark.parametrize(("impairment", "mtu", "path", "expected"), [
    ("loss", None, "capture", {"lost": 41, "written": 359}),
    ("duplication", None, "capture", {"repeated": 77, "written": 477}),
    ("corruption", None, "capture", {"altered": 77, "written": 400}),
    ("reorder", None, "capture", {"written": 400}),
    ("clean", FRAGMENTING, "capture", {"written": 400}),
    ("clean", FRAGMENTING, "packets", {"withheld": 240, "cited": 240, "written": 160}),
])
def test_the_prototype_table_reproduces(
    impairment: str, mtu: int | None, path: str, expected: dict[str, int],
):
    """The plan's prototype, seeds 0–9, 400 datagrams a row: the same counts through the scorer."""
    totals = dict.fromkeys(expected, 0)
    for seed in range(10):
        m = measure(prototype(seed, mtu, **dataclasses.asdict(ALONE[impairment])),
                    path=path)  # type: ignore[arg-type]
        for key in totals:
            totals[key] += getattr(m.delivery, key)
    assert totals == expected


def test_a_flow_the_packets_path_withholds_whole_opens_no_session():
    """Every datagram fragmented, every one cited: nothing to write, so no session (zipline#166)."""
    shape = (("c2s", 2000), ("s2c", 3000)) * 5
    r = run(Scenario(shape=shape, mtu=FRAGMENTING))
    m = measure(r, path="packets")

    assert m.accounting.sessions == m.accounting.expected_sessions == 0
    assert m.accounting.failures() == []
    assert m.delivery.cited == len(shape)
    assert measure(r).accounting.sessions == 1
