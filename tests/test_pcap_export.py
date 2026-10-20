"""The packets of a `.zpf` written to a pcap (#36): exactly the records, in time order.

An export for analysis, not a step in the chain, so the claim is narrow and
exact: every selected record is one pcap record holding its bytes as stored,
at its timestamp, under the link type its label names, merged across the
input's streams into time order.
"""

from __future__ import annotations

import pathlib
import shutil
import subprocess

import pytest
import zpf
from helpers import CAPTURES, VECTORS, packets_zpf
from packeteer.parse import iter_packets
from packeteer.pcap import LINKTYPE_ETHERNET, LINKTYPE_RAW

from zpfwire import packets_to_pcap
from zpfwire.__main__ import main


def capture_records(path: pathlib.Path) -> list[tuple[bytes, int, int, int | None]]:
    """Every record of a capture: frame, seconds, fraction, and where its IP header starts."""
    with iter_packets(path=path, decode_app=False, defragment=False) as reader:
        return [
            (p.source_records[0].data, p.ts_sec, p.ts_frac, p.offsets.get("ip"))
            for p in reader
        ]


def exported(path: pathlib.Path) -> tuple[int, list[tuple[bytes, int, int]]]:
    """Return a pcap's link type, and its records as ``(bytes, seconds, fraction)``."""
    with iter_packets(path=path, decode_app=False, defragment=False) as reader:
        link_type = reader.header.link_type
        return link_type, [(p.source_records[0].data, p.ts_sec, p.ts_frac) for p in reader]


def in_time_order(records: list[tuple[bytes, int, int]]) -> bool:
    """Report whether no record's timestamp precedes the one before it."""
    times = [(sec, frac) for _, sec, frac in records]
    return times == sorted(times)


@pytest.mark.parametrize("name", ["http.pcap", "fragmentation.pcap", "tcp_lossy_ts.pcap"])
def test_the_export_is_the_ip_layer_of_the_capture(tmp_path: pathlib.Path, name: str):
    """Same packets and timestamps, padding kept and fragments as fragments, in time order.

    Two directions' packets sharing a timestamp are taken in input-stream
    order, which a ``.zpf`` does not fix, so the order is compared as time
    order and the records as a multiset.
    """
    packets = packets_zpf(CAPTURES / name, tmp_path / "packets.zpf")
    export = packets_to_pcap(packets, tmp_path / "inner.pcap")

    link_type, records = exported(tmp_path / "inner.pcap")
    expected = [
        (frame[ip:], sec, frac) for frame, sec, frac, ip in capture_records(CAPTURES / name)
        if ip is not None
    ]
    assert link_type == LINKTYPE_RAW == export.link_type
    assert sorted(records) == sorted(expected)
    assert in_time_order(records)
    assert export.packets == export.records_selected == len(expected)


def test_ethernet_frames_export_as_ethernet(tmp_path: pathlib.Path):
    packets = packets_zpf(CAPTURES / "http.pcap", tmp_path / "packets.zpf",
                          label=zpf.NET_ETHERNET)
    packets_to_pcap(packets, tmp_path / "frames.pcap")

    link_type, records = exported(tmp_path / "frames.pcap")
    assert link_type == LINKTYPE_ETHERNET
    assert sorted(records) == sorted(
        (f, s, t) for f, s, t, _ in capture_records(CAPTURES / "http.pcap")
    )
    assert in_time_order(records)


def test_the_export_is_in_time_order_however_the_input_stores_it(tmp_path: pathlib.Path):
    """One direction stored before the other, as kober does, exports in wire order."""
    apart = packets_zpf(CAPTURES / "http_stream_1.pcap", tmp_path / "apart.zpf")
    mixed = packets_zpf(CAPTURES / "http_stream_1.pcap", tmp_path / "mixed.zpf",
                        interleave=True)
    packets_to_pcap(apart, tmp_path / "apart.pcap")
    packets_to_pcap(mixed, tmp_path / "mixed.pcap")

    _, from_apart = exported(tmp_path / "apart.pcap")
    _, from_mixed = exported(tmp_path / "mixed.pcap")
    assert in_time_order(from_apart) and in_time_order(from_mixed)
    assert sorted(from_apart) == sorted(from_mixed)


def test_a_filter_keeps_only_packets_it_can_judge(tmp_path: pathlib.Path):
    packets = packets_zpf(CAPTURES / "udp.pcap", tmp_path / "packets.zpf")
    everything = packets_to_pcap(packets, tmp_path / "all.pcap")
    none = packets_to_pcap(packets, tmp_path / "none.pcap", packet_filter=lambda _p: False)

    assert everything.packets > 0
    assert none.packets == 0 and none.filtered == everything.packets


def test_the_spec_tunnel_exports(tmp_path: pathlib.Path):
    export = packets_to_pcap(VECTORS / "tunnel" / "packets.zpf", tmp_path / "inner.pcap")

    _, records = exported(tmp_path / "inner.pcap")
    assert export.packets == len(records) == 3
    assert [r[0][:1] for r in records] == [b"\x45"] * 3


def test_two_link_types_are_refused(tmp_path: pathlib.Path):
    """One pcap has one link type, so a selection spanning two is refused."""
    mixed = tmp_path / "mixed.zpf"
    with zpf.create(mixed, tick_hz=1_000_000, produced_by="tests", produced_at=1) as writer:
        writer.add_source("capture", link_type=1)
        decoder = writer.add_decoder("tunnel", output_layer=zpf.OutputLayer.DECODED, version="0")
        session = writer.begin_session(proto="ip", key="tunnel")
        side = session.participant("tunnel", adjacency=zpf.Adjacency.UNITS)
        for i, label in enumerate((zpf.NET_IP, zpf.NET_ETHERNET)):
            session.record(side, ts=i, payload=b"\x45" + bytes(19),
                           decoded=zpf.Decoded(decoder=decoder, content_type=label))
        session.end()

    with pytest.raises(ValueError, match="two link types"):
        packets_to_pcap(mixed, tmp_path / "out.pcap")
    assert packets_to_pcap(mixed, tmp_path / "ip.pcap", content_type=zpf.NET_IP).packets == 1


@pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark is not installed")
def test_wireshark_reads_the_export(tmp_path: pathlib.Path):
    packets = packets_zpf(CAPTURES / "http.pcap", tmp_path / "packets.zpf")
    export = packets_to_pcap(packets, tmp_path / "inner.pcap")

    shown = subprocess.run(
        ["tshark", "-r", str(tmp_path / "inner.pcap"), "-T", "fields", "-e", "ip.src"],
        check=True, capture_output=True, text=True,
    ).stdout.split()
    assert len(shown) == export.packets


def test_the_cli_exports(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
                         capsys: pytest.CaptureFixture[str]):
    monkeypatch.setattr("sys.argv", ["zpfwire", "pcap", str(VECTORS / "tunnel" / "packets.zpf"),
                                     "-o", str(tmp_path / "inner.pcap")])
    main()

    assert "written      3 packets, link type 101" in capsys.readouterr().out


def test_the_cli_refuses_a_capture(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
                                   capsys: pytest.CaptureFixture[str]):
    monkeypatch.setattr("sys.argv", ["zpfwire", "pcap", str(CAPTURES / "http.pcap"),
                                     "-o", str(tmp_path / "out.pcap")])
    with pytest.raises(SystemExit) as exit_info:
        main()

    assert exit_info.value.code == 1
    assert "a capture already" in capsys.readouterr().err
