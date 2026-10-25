# Testing

Some 810 tests, native pytest style, in a top-level `tests/`.  Run them with:

```bash
.venv/bin/pytest
```

## The assertion that matters

Every file a test writes must read back cleanly:

```python
with zpf.open(out) as reader:
    for session in reader.sessions():
        list(session.records())
    assert reader.diagnostics == []
    assert reader.unplaceable == []
```

A file that does not survive `zpf.open` with both lists empty is not a
conversion, so this is not one test among many — it is the floor.  It runs on
every fixture, in both plain and sequenced modes.

It is two lists because since spec `0.19` a record the offset space cannot
place breaks no rule: the file reads clean, and `unplaceable` is the only
thing that says a producer discarded its own bytes.  The below-origin SYN this
project shipped for months is exactly what the second list would have caught.

Diagnostics accumulate as the file is read, so the sessions and their records
must be walked before the list is complete.  A test that opens a file and
checks diagnostics without reading it proves nothing.

`tests/helpers.py::to_zpf` does the whole cycle — convert, reopen, snapshot —
so most tests never call `zpf.open` themselves:

```python
out = to_zpf(CAPTURES / "no_errors.pcap", tmp_path)
assert out.diagnostics == []
assert out.only.stream(0) == b"..."
```

## Three ways to get an input

**Synthesised, for precision.**  packeteer's own `PacketBuilder` writes frames
into an `io.BytesIO`, which gives exact control over sequence numbers,
retransmits, reordering and loss — situations a recorded capture cannot be
nudged into on demand:

```python
buf = capture_of([
    Seg(1, b"abcdef", flags=TCP_PSH).frame(),
    Seg(4, b"defghi", flags=TCP_PSH).frame(),    # "def" repeats
])
```

`Seg` describes a segment relative to a stream, `capture_of` writes frames one
timestamp step apart, and `tcp_segments` combines them.  Use these for
anything where the *exact* byte you expect to be discarded matters.

**Recorded, for reality.**  `tests/captures/` holds fixtures copied from
packeteer's `testcases/`, each chosen for a behaviour:

| Fixture | What it exercises |
|---------|-------------------|
| `no_errors.pcap` | The clean baseline |
| `retransmission.pcap` | Overlap discard; must yield the same stream as the clean capture |
| `packet_loss.pcap` | A visible `seq_start` gap and a non-zero gap count |
| `delay.pcap` | Reordering |
| `payload_corruption.pcap`, `stray_1.pcap` | Disagreeing and stray retransmits |
| `sudden_termination_{1,2}.pcap` | Sessions ending with `rst` |
| `fragmentation.pcap` | IP reassembly — 287 records become 207 packets |
| `http_example.pcapng` | The payload `decode_app` protects, *and* three record-less sessions |
| `dns_example.pcapng`, `udp.pcap` | UDP datagram flows |
| `sctp.pcap` | A capture that converts nothing; every packet skipped |
| `http.pcap`, `http_gzip.pcap`, `http_stream_1.pcap` | Three real HTTP captures added directly rather than copied: a 3-conversation exchange with one retransmit, a 10-packet gzip response carrying the TCP Timestamps option, and a 4 140-packet, 20-conversation stream — the largest fixture, and the one to time against |
| `tcp_dup_ts.pcap` | Real **mirror duplicates**, from packeteer's `testcases/real/`: 10 segments seen twice with an identical sequence number *and* an identical TSval, captured on the router where the doubling happens.  The one shape the generator cannot make, since a resend is always rebuilt with a fresh clock — so the TSval is the only thing separating a duplicate from a retransmission |
| `tcp_lossy_ts.pcap` | A real **lossy** session carrying the Timestamps option, captured at the sender so the file holds each original *and* its resend: 14 ranges resent, every resend with a later TSval, every one answered by an ACK echoing *its* TSval.  From a sender's seat nothing was ever missing, so it produces no gap under any policy |
| `tcp_gap_ts.pcap` | The receiver-side twin of `tcp_lossy_ts`: the dropped segment is **absent**, its successors arrive first and are held behind the hole, and the resend that fills it carries a TSval **newer** than everything committed past it.  The only real traffic that produces gaps and late bytes — under a tight `reorder_window`, since the default absorbs every hole |
| `tcp_reorder_ts.pcap` | Originals **delayed rather than dropped**: 8 segments took a path 50 ms slower and arrive after 7–27 segments sent in later ticks, each with an **older** TSval — followed by the sender's spurious retransmission of the same bytes, which the receiver D-SACKs.  With `tcp_gap_ts`, the two answers a late byte can have |
| `tcp_corrupt_ts.pcap` | A segment **corrupted in flight** and resent: 5 originals reach the receiver with one payload bit flipped and a TCP checksum that fails — the only checksum failures in the file, collected with offload off — while the clean resend of each follows with a later TSval and is answered by an ACK echoing it.  The one fixture in which two copies of a range genuinely **differ**, and the first in which `bad_checksum` counts something that means what it says |
| `tcp_wrap_ts.pcap` | A real session whose sequence numbers **pass through 2³²**: the server's ISN sits 36 226 bytes below the wrap, so the receiver's ACKs wrap with the data while its TSecr keeps advancing, and four pre-wrap originals were delayed past every post-wrap segment.  Placeable in the offset space before any wrap-aware code existed, which is what it pins |

Several tests are parametrised over all of them — `ALL_CAPTURES` globs the
directory, so a new fixture is swept the moment it lands — which is how the
empty-session sequencing bug was caught.

**Repackaged, for a `.zpf` input.**  `tests/helpers.py::packets_zpf` writes
any capture as a `.zpf` of packet records, the shape a tunnel decryptor
writes: one record per frame, labelled `net:ip` (or `net:ethernet`, or a
private label), in two participants standing for the tunnel's directions,
either as a `units` unit sequence with a one-byte field record before each
packet, as zipline-kober writes, or `contiguous` with one declared break, as
the specification's vector does.  `test_packets.py` converts every fixture
both ways and asserts that the `.zpf` input gives the capture's sessions,
records, hints and timestamps, with the coverage, extent and splice checks
clean.  `tests/vectors/` vendors the specification's own `tunnel` vector at
a tag, byte for byte; its `packets.zpf` must rebuild its `inner.zpf`.

**Pinned, for the ones that must not move.**  `test_pins.py` records what the
`0.2.0` reassembler decided for each of the sixteen fixtures that predate the
Timestamps work, and asserts it on every run.  The six `tcp_*_ts.pcap`
fixtures are deliberately *not* pinned: they are where a `0.3.0` rule is
allowed to change the output, and each rule's test says what moved.  The pin
is a digest of the **decode**, not of the file — `helpers.decode_digest`
hashes every block in stored order with the File Header dropped, the Source
reduced to the capture's own digest and link type, and the Decoder to its
name, layer and `params_digest`.  A whole-file hash would move with the
wall-clock `produced_at`, the tool version in `produced_by` and the absolute
path in the Source `uri`, none of which is a decision; what remains is every
record, hint, flag, timestamp, participant, session end and `Undecoded`
citation, so a changed digest is a changed decision.  A new fixture has to
be added to one list or the other, and a test says so.

## What the suite is organised around

| File | Covers |
|------|--------|
| `test_capture.py` | The reader: the layer mapping, skip reasons, timestamps, byte offsets |
| `test_tcp.py` | The reassembler: ordering, overlap, gaps, coalescing, end reasons |
| `test_udp.py` | Datagram flows |
| `test_convert.py` | Orchestration, stats accounting, the fixture sweep |
| `test_provenance.py` | `Undecoded` blocks, `ts_first`, SYN records |
| `test_sequenced.py` | Causal ordering and what may be claimed |
| `test_checksum.py` | The `checksum` policy: what is dropped, cited and counted, and what is deliberately not read as a failure |
| `test_truncation.py` | Snaplen-cut captures: the count, the Source comment, and corruption staying unreportable |
| `test_pins.py` | The sixteen pre-Timestamps fixtures' decodes, pinned |
| `test_timestamps.py` | What the six real Timestamps captures say, rule by rule |
| `test_packets.py` | A `.zpf` of packets as input: the differential against each fixture's capture conversion, the tunnel vector, selection, coverage |
| `test_pcap_export.py` | The packets of a `.zpf` exported to a pcap |
| `test_cli.py` | Argument handling and output |
| `test_package.py` | What the package declares about itself — the specification URL held to `zpf.SPEC_VERSION` |

## Accounting invariants

Several tests assert identities rather than values, and they are the ones most
likely to catch a real regression:

```python
# every packet is converted, skipped, or filtered
stats.converted + sum(stats.skipped.values()) + stats.filtered == total

# every observed byte is written, discarded as a repeat (overlap or
# duplicate), dropped as late, rejected by PAWS, or — under checksum="drop"
# — discarded whole with its packet
(payload_bytes + overlap_bytes + duplicate_bytes + late_bytes + paws_bytes
 + checksum_dropped_bytes) == observed

# every discarded byte is either cited or counted as unlocatable
cited + unlocatable_bytes == (overlap_bytes + duplicate_bytes + late_bytes
                              + paws_bytes + checksum_dropped_bytes)
```

Each `0.3.0` rule that discards bytes added its counter to both identities
the day it landed; a rule that discards without counting fails the first,
and one that counts without citing fails the second.

Prefer adding to these over adding a test that pins a specific number.  A
number changes when a fixture or a default changes; an identity should not.

## Verifying against the capture

The strongest provenance tests read the capture file back and check that a
cited range holds the bytes it claims:

```python
capture = buf.getvalue()
block = out.undecoded[0]
assert capture[block.off_start:block.off_end] == b"hello"
```

This is what catches an off-by-one in offset arithmetic, which no amount of
internal consistency checking would.

## Writing a new test

- Name it as a sentence about behaviour:
  `test_a_discarded_retransmit_names_its_bytes_in_the_capture`.
- Put the *why* in the docstring, especially the specification rule involved.
  Several tests exist to pin down a rule that is not obvious from the code.
- Synthesise the capture when the exact bytes matter, use a fixture when
  realism matters.
- Go through `to_zpf` so the read-back assertion happens for free.

## The other two checks

```bash
ruff check src/ tests/ docs/ tools/ benchmarks/     # must be silent
.venv/bin/sphinx-build -W docs docs/_build/html     # warnings are errors
```

The docs build is a real test: `-W` means a broken cross-reference or an
autodoc target that no longer exists fails it.  Renaming a public function
without updating its API page will be caught here.
