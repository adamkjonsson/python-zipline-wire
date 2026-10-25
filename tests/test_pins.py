"""The sixteen fixtures whose decode must not move.

Every fixture that predates the ``0.3.0`` work is pinned here to what the
``0.2.0`` reassembler decided for it.  Only two of them carry the TCP
Timestamps option and neither repeats a segment, so nothing the option
decides applies to them, and a changed digest here is a bug in a phase that
was meant to leave them alone — or a deliberate break that the changelog has
to name by fixture.

The six Timestamps fixtures added for ``0.3.0`` are *not* pinned: they are
where the bytes are allowed to move, and each phase asserts what moved.

Since ``0.6.0`` stores pure ACKs by default (#37), the ``0.2.0`` decode is
what ``pure_acks=False`` writes, and is pinned that way; the default's own
decode of the same sixteen is pinned beside it.

The digest is of the decode, not the file — see
:func:`helpers.decode_digest` for what that leaves out and why.
"""

from __future__ import annotations

import pathlib

import pytest
from helpers import CAPTURES, decode_digest

from zpfwire import ReassemblyOptions, capture_to_zpf

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

PINNED_PURE_ACKS: dict[str, str] = {
    "delay.pcap":
        "sha256:67ceafe6746681d8f504e6b2d036d1e1a67830d34834f3be92e8031a884b4f4b",
    "dns_example.pcapng":
        "sha256:976cd6695a8df7c9763f120bf4f71250d43cd1ce4b31365193b722fafef8858d",
    "fragmentation.pcap":
        "sha256:2dd7247811a63f194e1fe3359112e4fb607b15af52b164ea15fc602219fe2697",
    "http.pcap":
        "sha256:eed2ee1f4b34feddcdb57c731def20363df94c8fae3bc65ae45c2665a8434511",
    "http_example.pcapng":
        "sha256:a1275155ef34966a37fc593f941ff4f21938c0e3fe0c09ca68c2edc7d7d4b17b",
    "http_gzip.pcap":
        "sha256:8772e5e0d5e7773e019e1c2f05507005fef486a425acfa70686dc21b1c31c75a",
    "http_stream_1.pcap":
        "sha256:d70ff30af9585105e7038f057194c908b0a87c4dcaa57879747860895b7a1aa0",
    "no_errors.pcap":
        "sha256:737518a72852e79850ea0be2613db0db77877d504a41915e5bd3cfe0e6a061f4",
    "packet_loss.pcap":
        "sha256:4e880517d2a19633f158ad40a0b87a8ba4fff9108479848197ccdbd467a6a54d",
    "payload_corruption.pcap":
        "sha256:b9a649482b13ecbb7ca8303bf35b7240c76f6c40c069310bb30cc5310f101557",
    "retransmission.pcap":
        "sha256:67660a8c7c16494e4899006b9a035ac4fab8639ef7f4d6dc0e27dc1d516a1b13",
    "sctp.pcap":
        "sha256:ce24ef9a7a157526737840cf379e312a31871e3a8b946f8619c6c48a981f3d09",
    "stray_1.pcap":
        "sha256:45fc7049746c4cb08ff7cd52c9c7985324f9dc27c3e140dab993cd11335c4661",
    "sudden_termination_1.pcap":
        "sha256:6c52a8a42d61e7bf31a132200867f0307ebde69b8f8ddd270a040ec7c3de2fe8",
    "sudden_termination_2.pcap":
        "sha256:a8a6d83c11a2da553002425a64b3a78105c657777d4ab1088efc37335dd69696",
    "udp.pcap":
        "sha256:f34393f69e11bf5ca29d0cee992ae3dfd8ebbc4ff721466114ddff431938e391",
}
"""The same fixtures under the ``0.6.0`` default, which stores pure ACKs (#37).

Recorded once ``test_pure_acks.py`` had shown that each is the opt-out
decode above plus one zero-length record per stored pure ACK, and nothing
else.  ``udp.pcap`` and ``sctp.pcap`` hold no TCP and still moved: the
Decoder's ``params_digest`` names the policy, and the policy changed.
"""


@pytest.mark.parametrize("name", sorted(PINNED))
def test_the_decode_of_a_pre_timestamps_fixture_has_not_moved(
    tmp_path: pathlib.Path, name: str,
):
    out = tmp_path / "out.zpf"
    capture_to_zpf(CAPTURES / name, out, options=ReassemblyOptions(pure_acks=False))

    assert decode_digest(out) == PINNED[name]


@pytest.mark.parametrize("name", sorted(PINNED_PURE_ACKS))
def test_the_default_decode_with_pure_acks_has_not_moved(tmp_path: pathlib.Path, name: str):
    out = tmp_path / "out.zpf"
    capture_to_zpf(CAPTURES / name, out)

    assert decode_digest(out) == PINNED_PURE_ACKS[name]


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
