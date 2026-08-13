# Testing

198 tests, native pytest style, in a top-level `tests/`.  Run them with:

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
```

A file that does not survive `zpf.open` with empty diagnostics is not a
conversion, so this is not one test among many — it is the floor.  It runs on
every fixture, in both plain and sequenced modes.

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

## Two ways to get a capture

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

Several tests are parametrised over all of them, which is how the
empty-session sequencing bug was caught.

## What the suite is organised around

| File | Covers |
|------|--------|
| `test_capture.py` | The reader: the layer mapping, skip reasons, timestamps, byte offsets |
| `test_tcp.py` | The reassembler: ordering, overlap, gaps, coalescing, end reasons |
| `test_udp.py` | Datagram flows |
| `test_convert.py` | Orchestration, stats accounting, the fixture sweep |
| `test_provenance.py` | `Undecoded` blocks, `ts_first`, SYN records |
| `test_sequenced.py` | Causal ordering and what may be claimed |
| `test_cli.py` | Argument handling and output |

## Accounting invariants

Several tests assert identities rather than values, and they are the ones most
likely to catch a real regression:

```python
# every packet is converted, skipped, or filtered
stats.converted + sum(stats.skipped.values()) + stats.filtered == total

# every observed byte is written, discarded as overlap, or dropped as late
payload_bytes + overlap_bytes + late_bytes == observed

# every discarded byte is either cited or counted as unlocatable
cited + unlocatable_bytes == overlap_bytes + late_bytes
```

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
ruff check src/ tests/ docs/                        # must be silent
.venv/bin/sphinx-build -W docs docs/_build/html     # warnings are errors
```

The docs build is a real test: `-W` means a broken cross-reference or an
autodoc target that no longer exists fails it.  Renaming a public function
without updating its API page will be caught here.
