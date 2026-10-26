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

``0.7.0`` moves eleven of them, by deliberate breaks the changelog names
by fixture.  Seven only gain the FIN records they lacked: a bare FIN after
a pushed last segment reached no record (#60) — ``fragmentation``,
``http``, ``http_example``, ``http_gzip``, ``http_stream_1`` (40 FINs),
``no_errors`` and ``stray_1``.  The other four gain theirs too, and move
for one more reason each: drained segments now end where their own PSH
says (#53), in ``delay`` and ``packet_loss``; and ``retransmission`` and
``payload_corruption`` lose ``retransmit`` flags that sat on records
holding no resent byte, so records the flags had split merge (#59).

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
        "sha256:16d42e03651abfefcfadf98f2a932ae6f33c3c115b0db0f61164fd0f5d398512",
    "dns_example.pcapng":
        "sha256:de6b86ea894ccbe004c8783989b1444a49838ccb7c5c206fd99920e3c2614115",
    "fragmentation.pcap":
        "sha256:4e4f195cd37494bfe1d75b8f652252ffd0ea5d6884c2f1133b313ecf90527035",
    "http.pcap":
        "sha256:16d164f8c74d06ba4ecd0e1625429709f41544eb29f4b46871ef4783a691b448",
    "http_example.pcapng":
        "sha256:7669dff25fee1124e4cb3cd277f6488d4352878faff4723c6e38a49bbf7bc1c9",
    "http_gzip.pcap":
        "sha256:149336b5648dfa06f4ae40dd144db3d6789f7daf872f7a4d58a6637bb0d3409c",
    "http_stream_1.pcap":
        "sha256:12a6e17cc664d80d51f22ac68ca48b7a1ff88d88cad77b0a64668f8c9b03e1e2",
    "no_errors.pcap":
        "sha256:a42a6c98d958495efb7ac759ca5f4fac676814fa72ed85f00ad4271ea76e67b8",
    "packet_loss.pcap":
        "sha256:471f24d3360118feaf766a5c9fc6c6f9e1bb11a3175e74adb6c5f3e4d0830645",
    "payload_corruption.pcap":
        "sha256:cde25744bdca79f8e003e037fc5351cdd50b17787df1860bb3c154da7a2b3aaf",
    "retransmission.pcap":
        "sha256:fe401fe9ec6cea780ed69dfd18e39b67cfd55dfd3604fd8414c6a47fe93f607d",
    "sctp.pcap":
        "sha256:9b2b0fabd4c907df514a658a029a3955711e620ee05718952c636f531a612864",
    "stray_1.pcap":
        "sha256:654e6fada44dde7b7b3f24a3610e752b3af6a001caab7b70a4faae9905ba8431",
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
        "sha256:66f08a418b547aaa26fca42a6c3730b68a41252f4e48e636d8976e30381fb883",
    "dns_example.pcapng":
        "sha256:976cd6695a8df7c9763f120bf4f71250d43cd1ce4b31365193b722fafef8858d",
    "fragmentation.pcap":
        "sha256:4d1b57613a143f0c5347d86d276399a9b523a0233fa2852f1d1df919acfeaf62",
    "http.pcap":
        "sha256:deaa3f7451ded6b3524018b52703b83fe9742f2be0971bc5842121f3f64c1b37",
    "http_example.pcapng":
        "sha256:0294260b61dba7991cf4ae409d9873dc6aa6eed9f14860b866e4a7694fdc7359",
    "http_gzip.pcap":
        "sha256:f136713a5cc206a1050e3c90cc5838f3328ba849cea200c389df31032cea3311",
    "http_stream_1.pcap":
        "sha256:e7e390d01b2b9241a93eb292f22da47e7227cb55baf82bb32803b27082e8a559",
    "no_errors.pcap":
        "sha256:e4efb9a93ddefea5851fa9127d3e7d8b3bafc0d44cf2802c9b2fb4b8b9779e69",
    "packet_loss.pcap":
        "sha256:9ae9e6e999002431460bc72476e3f2dc78eb242814e400f08405ff56baffbffd",
    "payload_corruption.pcap":
        "sha256:7a72d69b05102b069cc1339e6d0dc432f01beb3622e03c3c2a21d6ba45141d79",
    "retransmission.pcap":
        "sha256:f69a1643a4c6c85693b38684cd05d3377a4d0f3f1341f7d69ba29c37f2799912",
    "sctp.pcap":
        "sha256:ce24ef9a7a157526737840cf379e312a31871e3a8b946f8619c6c48a981f3d09",
    "stray_1.pcap":
        "sha256:df095079c3abf0ad206c3354a377db4921d1e63ee8a7a04a412c4a3fd7aba85f",
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
