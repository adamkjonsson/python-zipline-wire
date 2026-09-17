"""The sixteen fixtures whose decode must not move.

Every fixture that predates the ``0.3.0`` work is pinned here to what the
``0.2.0`` reassembler decided for it.  Only two of them carry the TCP
Timestamps option and neither repeats a segment, so nothing the option
decides applies to them, and a changed digest here is a bug in a phase that
was meant to leave them alone — or a deliberate break that the changelog has
to name by fixture.

The six Timestamps fixtures added for ``0.3.0`` are *not* pinned: they are
where the bytes are allowed to move, and each phase asserts what moved.

The digest is of the decode, not the file — see
:func:`helpers.decode_digest` for what that leaves out and why.
"""

from __future__ import annotations

import pathlib

import pytest
from helpers import CAPTURES, decode_digest

from zpfwire import capture_to_zpf

PINNED: dict[str, str] = {
    "delay.pcap":
        "sha256:511351a6a1887623eeae22ac789de722990e99aa705925a6aa339d40691caddf",
    "dns_example.pcapng":
        "sha256:de6b86ea894ccbe004c8783989b1444a49838ccb7c5c206fd99920e3c2614115",
    "fragmentation.pcap":
        "sha256:cb97928045ea38d4bfe52d2731d3c07c56906a14e8ec689e8a58f0ea75aed9b9",
    "http.pcap":
        "sha256:8a432b8fea3ccd8bf89c6c06543e46f1a83d83cee4431ae725a77cd2f92d8271",
    "http_example.pcapng":
        "sha256:bd05a35f65ecc6ddaa2a677ac445a3dc9e47a4d180bd57c2022b83388706a049",
    "http_gzip.pcap":
        "sha256:15d92138439e7a8454525fb337967a470cd63ca534b4a8dd3f84d4b5b6c5e678",
    "http_stream_1.pcap":
        "sha256:b149024c0d39e7784e8ffb23794a764a0042206378340c12285760c8e89397d7",
    "no_errors.pcap":
        "sha256:85040d6ced7a442c33535d1343ffa5643a1596c9cb77e52e8407e1d45fb6091d",
    "packet_loss.pcap":
        "sha256:6dae1da715dfaafdfd302f51a4c2af0329bf8c381b67798a95d25b3d14bd47d3",
    "payload_corruption.pcap":
        "sha256:eaf62e08df5b58a85edde36c82859628459b7b501e019173ad8938b254bd7d4f",
    "retransmission.pcap":
        "sha256:0eba04f3c32711ee5f5dce4bedcd2f5b02990c4ed0cf90fcde4257664a704f28",
    "sctp.pcap":
        "sha256:9b2b0fabd4c907df514a658a029a3955711e620ee05718952c636f531a612864",
    "stray_1.pcap":
        "sha256:f6cb490fe44727a003aab5cf11e86e083200f57605e593a2230318375f1b2b4a",
    "sudden_termination_1.pcap":
        "sha256:6005b9090f0bf25d4c9f64d160fafda8471072c75b79ded688ac8ae9dc7f06e8",
    "sudden_termination_2.pcap":
        "sha256:00f9a6075f3a3efe7776031772a08b64cdaf39a56babe4bbcbc02afe5fb75adb",
    "udp.pcap":
        "sha256:d4ef60d134715278772902668e487f00743c35ac1413d2ca898a3d60a95604b1",
}
"""What the ``0.2.0`` reassembler decided, recorded before ``0.3.0`` changed it."""

TIMESTAMPS_FIXTURES = frozenset({
    "tcp_corrupt_ts.pcap",
    "tcp_dup_ts.pcap",
    "tcp_gap_ts.pcap",
    "tcp_lossy_ts.pcap",
    "tcp_reorder_ts.pcap",
    "tcp_wrap_ts.pcap",
})
"""The fixtures ``0.3.0`` is allowed to change, and so does not pin."""


@pytest.mark.parametrize("name", sorted(PINNED))
def test_the_decode_of_a_pre_timestamps_fixture_has_not_moved(
    tmp_path: pathlib.Path, name: str,
):
    out = tmp_path / "out.zpf"
    capture_to_zpf(CAPTURES / name, out)

    assert decode_digest(out) == PINNED[name]


def test_every_fixture_is_either_pinned_or_a_timestamps_fixture():
    """A new fixture has to say which side of the line it is on."""
    present = {p.name for p in CAPTURES.glob("*.pcap*")}

    assert present == set(PINNED) | TIMESTAMPS_FIXTURES


def test_the_digest_ignores_provenance(tmp_path: pathlib.Path):
    """The path the capture was read from and the build stamp are not decisions."""
    copy = tmp_path / "renamed.pcap"
    copy.write_bytes((CAPTURES / "no_errors.pcap").read_bytes())
    first = tmp_path / "first.zpf"
    second = tmp_path / "second.zpf"
    capture_to_zpf(CAPTURES / "no_errors.pcap", first, produced_at=1)
    capture_to_zpf(copy, second, produced_at=2)

    assert decode_digest(first) == decode_digest(second)
