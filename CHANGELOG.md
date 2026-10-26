# Changelog

All notable changes to zpfwire are recorded in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
with the usual 0.x caveat: **while the version is below 1.0, a minor bump
(0.1 → 0.2) may break backwards compatibility.**  Breaking entries are marked
**Breaking:** so they are easy to find before upgrading.

Change types used here are the Keep a Changelog set — *Added*, *Changed*,
*Deprecated*, *Removed*, *Fixed*, *Security* — plus a project-specific
*Documentation* section for docs-only work.  Types with nothing to report are
omitted.

`zpfwire` writes files against one version of the Zipline Payload Format, and
the two numbers are separate counters: each release below names the spec
version it was built against, which is `zpf.SPEC_VERSION` at the time.  The
two siblings it is glue between — [packeteer](https://github.com/adamkjonsson/packeteer)
and [python-zipline](https://github.com/adamkjonsson/python-zipline) — are
named per release too, since neither is on PyPI and both move underneath this
one.

---

## [Unreleased]

<!--
Add entries here as work lands, under the change types listed above.
Releasing: rename this heading to `## [X.Y.Z] - YYYY-MM-DD`, add a fresh
Unreleased section above it, drop any `.devN` suffix from the version in
pyproject.toml, update the link definitions at the bottom of this file, tag
`vX.Y.Z`, and close the release's issues and milestone.
-->

Every change below that moves output was found by `tools/fidelity.py`
(#52), which scores a conversion against the traffic packeteer generated it
from. The plan quotes each fix's cells before and after. For anyone
reproducing a `.zpf`, eleven of the sixteen pinned fixtures decode
differently: `delay`, `fragmentation`, `http`, `http_example`, `http_gzip`,
`http_stream_1`, `no_errors`, `packet_loss`, `payload_corruption`,
`retransmission` and `stray_1`. So does `tcp_wrap_ts`. The entries below say
which change moves which.

### Added

- `ReassemblyOptions.acked_hold` and `--acked-hold SECONDS`: under
  `favor-acked`, how long a closed run may wait for the receiver's covering
  ack, in place of `flush_timeout` and `reorder_window`
  ([#32](https://github.com/adamkjonsson/python-zipline-wire/issues/32)).
  A resend comes an RTO after the copy it replaces, and on a bulk transfer
  at a 1 s initial RTO the default bounds release about 90 corrupted copies
  a run before their resend arrives. A 10 s hold releases none. `None` by
  default, and left out of `params_digest` while `None`.
- `ReassemblyOptions.require_timestamps` and `--require-timestamps`: drop a
  segment without the TCP Timestamps option on a connection whose SYNs both
  carried it, as RFC 7323 §3.2 has a receiver do. Its bytes, ack and flags
  are dropped, and its payload is cited as `timestamp-missing`
  ([#57](https://github.com/adamkjonsson/python-zipline-wire/issues/57)).
  Forged segments usually lack the option, and with it every stray scenario
  in the fidelity sweep converts exactly. Off by default, because a
  middlebox stripping options mid-connection would make it drop real data;
  no real capture in the test corpus loses a segment to it. Counted in
  `ConversionStats.ts_missing` and `ts_missing_bytes`, and left out of
  `params_digest` while off. `zpfwire.flow.REASON_TS_MISSING` names the
  reason.

### Changed

- **Breaking:** a coalesced run ends where the peer answers it
  ([#55](https://github.com/adamkjonsson/python-zipline-wire/issues/55)).
  A peer segment carrying data or a FIN that acknowledges bytes of the open
  run closes it. Before, a run ended only at PSH, so an unpushed request's
  run took in the next request, after the response had answered it. The
  record then held bytes from both sides of the response, and both the
  causal merge and `--sequenced` placed it after the response, so the
  response read before the request it answers. That happened in 35 of 40
  generated request/response runs. A pure ACK does not close a run, so a
  one-way transfer still coalesces. Under `favor-acked`, a copy swapped in
  for the one first seen is now a **record of its own** with its own
  `timestamp` and `ack`. It is a resend sent after the peer answered the
  bytes around it, and in one record with them it dated the whole run
  after that answer. Files with request/response traffic sent without PSH,
  and `favor-acked` files with a swap, are written differently; none of the
  pinned fixtures is.
- **Breaking:** a run ends at PSH where the pushed segment's bytes join it,
  in sequence order, and `coalesce=False` holds for segments drained from
  the reorder buffer
  ([#53](https://github.com/adamkjonsson/python-zipline-wire/issues/53)).
  Before, the flush followed the *arriving* packet, with two consequences:
  - a held, pushed segment ended whichever unrelated run was open;
  - a backlog drained after a hole filled became one record whatever PSHs it
    held, even under `coalesce=False`, contrary to that option's documented
    "each segment becomes its own record".

  Moves `delay` (24 → 30 records) and `packet_loss` (8 → 35), along with
  the FIN records below.
- **Breaking:** `retransmit` flags the record holding the resent range
  ([#59](https://github.com/adamkjonsson/python-zipline-wire/issues/59)).
  Before, it was set on whichever run was open when the resend was
  discarded, which could be a later record holding no resent byte. A
  record cannot change once written, and a resend usually comes an RTO
  later, so most resends now flag nothing. Their `overlap-discarded`
  citation is what says they happened. Moves `payload_corruption` (5
  spurious flags) and `retransmission` (7), whose records the flags had
  split now merge, and `tcp_wrap_ts` (1).
- **Breaking:** a bare FIN after a pushed last segment, the usual way a
  sender closes, is written as a zero-length record at its sequence number,
  as a pure ACK is
  ([#60](https://github.com/adamkjonsson/python-zipline-wire/issues/60)).
  It reached no record before. A FIN beyond a hole ends the record that ends
  where it sits, not the run open when it arrived. Adds FIN records to all
  eleven moved fixtures, including 40 to `http_stream_1`.
- **Breaking:** a capture-point copy of a resend that was itself discarded
  is judged a copy, cited `duplicate-discarded` and counted in
  `duplicates`, not taken for another resend
  ([#56](https://github.com/adamkjonsson/python-zipline-wire/issues/56)).
  Every such copy in the fidelity sweep was misjudged, 9,681 of them; none
  is now. No stream byte moves; citations and stats do.
- **Breaking:** a repeat is a capture-point copy only if its bytes equal
  those already accepted, as well as its clock
  ([#61](https://github.com/adamkjonsson/python-zipline-wire/issues/61)).
  A mirror's copy is byte-identical by definition. A segment forged with
  the real segment's TSval used to pass as one: as `duplicate-discarded`
  when it lost, and, arriving first, by making the real segment its "copy",
  which `favor-acked` never contests. The bytes are compared directly while
  a run still holds them. Once they are written, a copy has to be the same
  packet: the range of one remembered transmission, and a CRC32 of its
  bytes, kept for each accepted segment. Under `favor-acked`, a receiver's
  echo that names *both* copies, which such a forgery makes it do, is
  counted in `acked_fallback_bytes` like one that names neither. No fixture
  moves: 198 of 198 outputs are byte-identical to the commit before. In
  the fidelity sweep's stamped-stray cells, segments taken for a copy of a
  forgery, or forgeries taken for a copy, go from 18 to 0 under every
  policy, `coalesce=False` included, where every record is written at
  once. Reassembly is 2–6% slower per packet on the benchmark's synthetic
  shapes, for the CRC, and unchanged on `http_stream_1.pcap`.
- **Breaking:** under `favor-acked`, a copy of bytes the peer has already
  acknowledged is not contested: the receiver chose with only the first
  copy to hand, and discards a later one as old data
  ([#62](https://github.com/adamkjonsson/python-zipline-wire/issues/62)).
  It is discarded and cited `overlap-discarded`, as before `favor-acked`.
  Contested, it was decided by the next covering ack, whose echo can name
  a later segment sent in the copy's clock tick, so a forgery could be
  swapped in for the bytes the receiver kept. An ack only counts here if
  it acknowledges bytes seen sent, since a forgery copies a later
  segment's ack. In the fidelity sweep's stamped-stray cells, `favor-acked`
  runs keeping forged bytes that nothing counts go from 49 to 8 of 224,
  and no run is worse. No fixture moves. The 8 are a forged
  acknowledgement, which `docs/reference/limits.md` now documents.
- **Breaking:** under `favor-acked`, a repeat whose original has aged out
  of the reassembler's memory (`ts_fallback["stale"]`) is contested like a
  resend, since it carries its own clock for the receiver's echo to match.
  A resend a full RTO behind a bulk transfer is usually such a repeat. More
  corrupted copies are swapped out, so `favor-acked` files with late
  resends are written differently
  ([#54](https://github.com/adamkjonsson/python-zipline-wire/issues/54)).

- **The packeteer range is `>=0.21.0,<0.22`**, up from `>=0.16.0,<0.21`.
  The floor names what the *suite* needs, as it has since `0.16.0`:
  `0.21.0` fails every corrupted segment's checksum with data in both
  directions ([packeteer#227](https://github.com/adamkjonsson/packeteer/issues/227)),
  which the fidelity tests of two-way corruption depend on. Before it, half
  those runs carried a corrupted segment that verified, and were voided
  rather than scored. The code needs nothing newer.

### Fixed

- `acked_fallback_bytes` counts every contested byte `favor-acked` wrote as
  `favor-old` would ([#54](https://github.com/adamkjonsson/python-zipline-wire/issues/54)).
  Two kinds went uncounted before:
  - a resend arriving after a bound released its run, judged against a
    digest of each released segment as written;
  - an ack whose echo named neither copy, as a cumulative ack over several
    resends does.

  On a 1 MiB transfer at a 1 s RTO, the stat went from 0 to exactly the
  bytes left wrong.
- `capture_to_zpf`, `convert` and `packets_to_zpf` annotate `sink` as
  `str | PathLike[str] | IO[bytes] | IO[str]`. All three take
  `face="jsonl"`, which zpf writes to a text stream, so a caller passing an
  `io.StringIO` was right at runtime and wrong to a type checker
  ([#58](https://github.com/adamkjonsson/python-zipline-wire/issues/58)).

### Documentation

- The contributing guide describes `tools/fidelity.py`, which measures how
  well a conversion represents the traffic that was actually sent. packeteer
  generates a TCP conversation under chosen impairments, and the tool scores
  the converted `.zpf` against what each side sent: byte by byte, in causal
  order and in time ([#52](https://github.com/adamkjonsson/python-zipline-wire/issues/52)).
  Its strays can carry a Timestamps option
  ([packeteer#228](https://github.com/adamkjonsson/packeteer/issues/228)), so
  `require_timestamps` is measured against a forger who knows the clock as
  well as one who does not.
- The testing page lists `test_fidelity.py`, `test_pure_acks.py` and
  `test_tcp_order.py`. The contributing guide's byte-identity commands no
  longer assume `0.5.0`: `tools/byte_identity.py` now compares against the
  last release tag by default. Pages that quote the fidelity tool say where
  it is.
- The reassembler's internals page describes this release's run
  boundaries, flags, FIN records, judgement and `favor-acked` hold. It no
  longer describes two helpers removed in `0.3.0` and `0.6.0`, nor says a
  bare FIN gets no record. The zpf mapping documents the zero-length pure-ACK
  and FIN records, the first missing since `0.6.0`, and where `retransmit`
  now goes. `ReassemblyOptions.overlap` no longer calls `favor-old` the only
  policy, which it has not been since `0.3.0`.

---

## [0.6.0] - 2026-10-25

**The performance release, and the pure-ACK release.**  Writes spec
**v0.23** (`zpf.SPEC_VERSION == (0, 23)`), unchanged from `0.5.0`, against
packeteer **0.20.0** and python-zipline **0.7.0**.

**One Breaking change, with a way back.**  Pure ACKs are now stored as
zero-length records by default
([#37](https://github.com/adamkjonsson/python-zipline-wire/issues/37)), as
the specification advises: every pure ACK is an edge for the causal merge,
the receiver's reaction times are in the file, and a `.zpf` input cites the
packet instead of leaving it `skipped`.  So the bytes of nearly every TCP
conversion move.  **`pure_acks=False` / `--no-pure-acks` writes exactly what
`0.5.0` wrote**, `params_digest` included, checked against the `v0.5.0` tag
on 198 outputs.  It costs records, about one per data segment:
`http_stream_1.pcap` converts 29% slower and 23% larger by default.  That is
paid once at write, for information every reader gets.  A second, narrow
break is a fix: a committed gap no longer claims a resend 4 GiB later that
carries its sequence numbers
([#45](https://github.com/adamkjonsson/python-zipline-wire/issues/45)).

**The reassembler no longer slows with what it holds**
([#43](https://github.com/adamkjonsson/python-zipline-wire/issues/43),
[#44](https://github.com/adamkjonsson/python-zipline-wire/issues/44),
[#45](https://github.com/adamkjonsson/python-zipline-wire/issues/45),
[#46](https://github.com/adamkjonsson/python-zipline-wire/issues/46)),
writing the same bytes as before:

| µs per packet | `0.5.0` | `0.6.0` |
| --- | --- | --- |
| resends carrying TSvals, 10-byte segments | 212 | 2.7 |
| holes with 2,000 small segments waiting | 70 | 4.6 |
| 1 in 50 lost, 80,000 packets | 10.1 | 2.9 |
| in order | 5.4 | 4.6 |

Parsing is faster too, by packeteer `0.20.0`'s checksum in C
([packeteer#213](https://github.com/adamkjonsson/packeteer/issues/213), found
here).  The siblings are now ranges closed above and installed from their
release tags, locally and in CI
([#41](https://github.com/adamkjonsson/python-zipline-wire/issues/41),
[#42](https://github.com/adamkjonsson/python-zipline-wire/issues/42)).
Open upstream: [zipline#168](https://github.com/adamkjonsson/zipline/issues/168),
the extent past a FIN, and
[python-zipline#101](https://github.com/adamkjonsson/python-zipline/issues/101),
the writer's cost per record, which now matters most here.

### Added

- **`ReassemblyOptions.pure_acks`**, CLI `--no-pure-acks`
  ([#37](https://github.com/adamkjonsson/python-zipline-wire/issues/37)):
  whether a TCP segment carrying no bytes and no SYN, FIN or RST is stored
  as a zero-length record holding its `ack`. On by default; see *Changed*.
  `ConversionStats` gains `pure_acks`, the records written for them, and
  `pure_acks_unstored`, those that arrived behind bytes of their sender's
  already placed, where no stored order fits them. Their `ack` folds into the
  next record, as with the option off. The summary reports both.

### Changed

- **Breaking: pure ACKs are stored by default**
  ([#37](https://github.com/adamkjonsson/python-zipline-wire/issues/37)),
  as the specification advises since spec `0.23`. Each is a zero-length
  record at its wire sequence number, carrying its `ack`. It has no end, so
  no edge runs from it, but its `ack` orders it after the peer bytes it
  covers. The causal merge gets an edge per pure ACK, the receiver's
  reaction times are in the file, and over a `.zpf` input the packet is
  cited instead of left `skipped`.
  - **The bytes of nearly every TCP conversion move**, and the Decoder's
    `params_digest` with them. No data record changes: every fixture, under
    every policy, converts to what the opt-out writes plus one zero-length
    record per stored pure ACK. A stream with a final pure ACK reaches one
    position past its last byte, the FIN's, which the ACK's wire number
    sits beyond; whether an extent should count it is
    [zipline#168](https://github.com/adamkjonsson/zipline/issues/168).
  - **To get `0.5.0`'s output**, pass `pure_acks=False` or `--no-pure-acks`.
    That writes exactly what `0.5.0` wrote, `params_digest` included, so
    an existing file is reproduced byte for byte.
  - **It costs records.** On `http_stream_1.pcap`, a 4,140-packet HTTP
    capture, output grows 23% (543,900 → 667,500 bytes) and conversion
    takes about 30% longer (119 → 154 ms), almost all of it the `zpf`
    writer's work per record
    ([python-zipline#101](https://github.com/adamkjonsson/python-zipline/issues/101)).
    That is more than the speed-ups below save on clean traffic, so by
    default this release converts such a capture more slowly than `0.5.0`
    did. The trade is deliberate: the specification's premise is that a
    file is read far more often than written, and the cost is paid once,
    for information every reader gets. That capture carries 2,060 pure
    ACKs beside 2,000 data segments, so its records double.

- **Breaking: a committed gap no longer claims a resend 4 GiB later that
  carries its sequence numbers**
  ([#45](https://github.com/adamkjonsson/python-zipline-wire/issues/45)).
  A gap is kept as wire sequence numbers, which come round again every
  2**32 bytes. Once a direction had moved 4 GiB past a loss, it was carrying
  the lost range's numbers again. A resend there was then counted as
  `late_bytes` and cited `late-arrival` against the old gap, when it was a
  resend of bytes the direction had accepted: `overlap_bytes`, cited
  `overlap-discarded`, with the record flagged `retransmit`. The output
  moves only for a direction longer than 4 GiB that committed a gap and
  later repeats bytes whose numbers fall inside it. Nothing a caller passes
  changes; to reproduce such a file exactly, convert with `0.5.0`.
- **TCP reassembly no longer slows with the depth of the reorder buffer,
  the length of the repeat history, or the number of gaps committed**
  ([#43](https://github.com/adamkjonsson/python-zipline-wire/issues/43),
  [#44](https://github.com/adamkjonsson/python-zipline-wire/issues/44),
  [#45](https://github.com/adamkjonsson/python-zipline-wire/issues/45)).
  - **The next held segment is found in constant time.** It took a scan of
    every held segment, so filling a hole with *P* segments waiting behind
    it cost O(*P*²).
  - **A repeated range is found in `recent` by bisection.** Every repeat
    carrying a TSval scanned all of `recent`, which with small segments
    holds tens of thousands of entries.
  - **A repeat is checked only against the gaps it can reach.** Every
    repeat scanned, and sorted, every gap the connection had ever
    committed, so a long lossy connection slowed down the longer it ran.
  - **A record's flags come from a table.** `RecordFlags` is a `Flag` enum
    whose `|` runs in Python, and building each record's flags bit by bit
    was about a seventh of the in-order path
    ([#46](https://github.com/adamkjonsson/python-zipline-wire/issues/46)).
  - **A segment drained from the reorder buffer is appended from its own
    fields**, not from a packet view built to carry three of them (#46).

  Every conversion writes the same bytes as `0.5.0`, except in the 4 GiB
  case above. Median µs per packet, CPython 3.14 on arm64:

  | Traffic | Before | After |
  | --- | --- | --- |
  | resends carrying TSvals, 10-byte segments | 212 | 2.7 |
  | the same, 100-byte segments | 54 | 2.8 |
  | holes with 2,000 small segments waiting | 70 | 4.6 |
  | holes with 170 full-size segments waiting | 12.0 | 4.4 |
  | 1 in 50 lost, 80,000 packets, late copies | 10.1 | 2.9 |
  | in order | 5.4 | 4.6 |

  A capture of clean traffic (`http_stream_1.pcap`) converts about 4%
  faster; there, most of the time is in packeteer's parse and the `zpf`
  writer.
- **Both siblings are declared as ranges closed above**: `zpf>=0.7.0,<0.8`
  and `packeteer>=0.16.0,<0.21`
  ([#41](https://github.com/adamkjonsson/python-zipline-wire/issues/41)).
  Each sibling is in `0.x` and may break at any minor, so the range stops
  at the newest minor this tree was tested against, and moves when the
  suite has passed on the next. The `zpf` floor rises from `0.6.0` to
  `0.7.0`, which writes the same spec (`0.23`), so no file and no reader is
  affected. A resolver that held `zpf 0.6.x` now takes `0.7.x`.
- **The development environment installs the sibling releases, not the
  checkouts**
  ([#42](https://github.com/adamkjonsson/python-zipline-wire/issues/42)).
  `requirements.txt` installs packeteer `0.20.0` and python-zipline `0.7.0`
  from their tags, so `.venv` tests what the wheel declares and `pip list`
  says what is running. Before, an editable install of each checkout went
  on reporting the version it was installed at while running whatever was
  checked out. CI did the same with the siblings' default branches, and now
  installs the tags too. Working against the checkouts moves to a second
  venv, `.venv-dev`, built with `requirements-dev-siblings.txt`. Every test
  run's header now prints each sibling's version and the file it was
  imported from, which disagree exactly when an install's metadata is
  stale.

### Fixed

- **`describe_source` hashes a capture given as a stream a megabyte at a
  time**, as it already did one given as a path
  ([#47](https://github.com/adamkjonsson/python-zipline-wire/issues/47)).
  It read the whole stream into memory, so `capture_to_zpf(stream, …)` held
  the entire capture just to compute its digest. The digest is unchanged,
  and the stream is still left where it was found.

### Documentation

- Installation, contributing and the README describe the two venvs, and
  that a new sibling release moves the tag in `requirements.txt` and the
  range in `pyproject.toml` together.
- The reassembly guide has a section on `pure_acks`, the internals page on
  the reassembler explains where a pure ACK's record is placed, and the
  pages that said a conversation of pure ACKs produces no records say when
  it does.
- The release sweep: the CLI transcripts in the README, the overview and
  `convert`'s page were rerun, since their record counts now include pure
  ACKs; `limits.md` describes the dependency ranges and tagged installs
  instead of floors and editable checkouts, and names the two per-direction
  lists that grow for a connection's lifetime; `upstream-first.md` counts
  forty-two issues, three open, with rows for packeteer#213,
  python-zipline#101 and zipline#168; the test count, the module map and
  the `packets` and `tcp` module docstrings are current.
- The contributing guide describes `tools/byte_identity.py`, which checks
  that this tree converts every fixture to the bytes a release wrote, and
  `benchmarks/reassembly.py`, which times the reassembler. Both are linted
  with the rest of the tree.

---

## [0.5.0] - 2026-10-20

**The `.zpf`-input release.**  Writes spec **v0.23**
(`zpf.SPEC_VERSION == (0, 23)`), up from `0.21`, against packeteer
**0.18.0** and python-zipline **0.6.0**
([#38](https://github.com/adamkjonsson/python-zipline-wire/issues/38)).
No python-zipline release implements `0.22`, which `0.23` followed the same
day, and this release takes both.  The floors are python-zipline `0.6.0`,
the first release that implements `0.23`, and packeteer `0.16.0`.  The `0.x`
rule as before: a `0.21` reader refuses the files this release writes, and
a `0.23` reader refuses `0.4.0`'s.  For the same input and options nothing
else moves: every fixture, under both overlap policies and with and without
`--sequenced`, converts to the bytes `0.4.0` wrote but for the version
stamp in the File Header.

**Spec `0.22` and `0.23`** answer three issues filed from this project, and
fix one more found upstream.  An **`ack` is now a position**, unwrapped
along its sender's records into the peer's offset space as offsets have
been since `0.21`, so the causal check compares plain integers at any
stream length ([zipline#151](https://github.com/adamkjonsson/zipline/issues/151),
the one shape `0.4.0` could not write).  A **sequence-anchored transport
output may cite across its input's seams**
([zipline#152](https://github.com/adamkjonsson/zipline/issues/152)), and
**`net:ip` and `net:ethernet`** name one network packet
([zipline#153](https://github.com/adamkjonsson/zipline/issues/153)); both
are what a stage reading a `.zpf` of packets needs, and this release is
the first to have one — see *Added*.  A record's end is now **one past the last sequence number it
occupies**, so a stored pure ACK draws no edge
([zipline#160](https://github.com/adamkjonsson/zipline/issues/160)); this
tree stores no pure ACKs, so nothing it writes is affected.

### Added

- **A `.zpf` of packets converts into sessions**
  ([#35](https://github.com/adamkjonsson/python-zipline-wire/issues/35)):
  **`zpfwire.packets_to_zpf(source, sink, …)`**, the
  `packets.zpf → inner.zpf` hop of the specification's decrypted-tunnel
  chain.  A stage that decrypts a tunnel leaves its inner traffic as
  records, one per packet; this runs the same reassembly a capture gets over
  them and writes a transport-layer file whose every record cites the input
  packets it was built from.  It is built on python-zipline's
  `sessionize_stage`, which keeps the coverage guarantee, the `skipped`
  auto-fill and each Session End's whole-stream `input_extents`.  Its
  keywords are `capture_to_zpf`'s, less `tick_hz` and `link_type`, which a
  `.zpf` states itself, plus the selection:
  - **`content_type=None` selects `net:ip` and `net:ethernet`**, the
    format's own labels since spec `0.22`, each parsed as the link type it
    names.  Another label selects records a decoder typed privately, such as
    zipline-kober's `dec:ip-packet`, parsed as raw IP unless `link_type`
    says otherwise.
  - **A packet is cited whole**, headers included, by every record its bytes
    or flags reached; a packet this tree discarded is marked with the reason
    it would carry on a capture (`duplicate-discarded`, `late-arrival`,
    `bad-checksum` …); anything else nothing cited — a pure ACK, a record
    that is not a packet, a filtered flow — is left to the stage's `skipped`.
  - **Records coalesce over the input's seams**, as zipline#152 allows a
    record carrying `seq_start`, so over every fixture the sessions, records,
    hints, flags and timestamps are those of the capture they came from.
  - **The input is merged into timestamp order** across its streams, since a
    decrypting stage stores one tunnel direction before the other.  Two
    directions' records sharing a timestamp have no order in a `.zpf`, and
    are taken by input stream.
  - **A fragmented UDP datagram is not converted**: no record without
    `seq_start` may cite several input units, so its fragments are marked
    `undecodable` and counted as `SKIP_FRAGMENTED_UDP`
    ([zipline#166](https://github.com/adamkjonsson/zipline/issues/166)).
    Fragmented TCP is one record, as on a capture.
  - **A flow that resumes gets a second session** on the same key, after its
    timeout or past a `capture-gap`, as on a capture.  The JSON-Lines face is
    written as for a capture, and the File Header names `zpfwire` as its
    `creator`.
- **`zpfwire convert` takes a `.zpf` of packets** as well as a capture, told
  apart by its first bytes: `zpfwire convert packets.zpf -o inner.zpf`.
  **`--content-type LABEL`** selects a label other than `net:`'s, such as
  `dec:ip-packet`, and `--link-type` then says how to parse it; every filter
  applies to the inner packets, and `--jsonl` writes the JSON-Lines
  projection.  `--tick-hz` is refused with a `.zpf`, and `--content-type`
  with a capture.  The summary
  opens with an `input` line counting the records read and selected, and
  when none was selected a note names `--content-type`.  `zpfwire info`
  refuses a `.zpf`.
- **The packets of a `.zpf` export to a pcap**, for Wireshark
  ([#36](https://github.com/adamkjonsson/python-zipline-wire/issues/36)):
  **`zpfwire pcap packets.zpf -o inner.pcap`**, and
  **`zpfwire.packets_to_pcap(source, sink, …)`** returning a **`PcapExport`**.
  The same records `packets_to_zpf` selects, merged into time order, each
  written exactly as stored — padding kept, fragments as fragments — under
  the link type its label names; a selection of two link types is refused.
  An export for analysis: a pcap cites nothing, so `convert` is what keeps
  the chain.  It streams, since packeteer's writer takes any iterable
  ([packeteer#204](https://github.com/adamkjonsson/packeteer/issues/204)).
- **`zpfwire.input_kind(source)`** says whether an input is a `.zpf` or a
  capture, by the format's own check of its first bytes.
- **`PacketRecordReader`**, the `.zpf` counterpart of `CaptureReader`;
  **`RecordSink`**, with **`CaptureSink`** and **`PacketSink`**, where a
  tracker's session goes; **`REASON_UNDECODABLE`** and
  **`SKIP_FRAGMENTED_UDP`**; and **`ConversionStats.records_read`** and
  **`records_selected`**, with an `input` summary line for a `.zpf` input.

### Changed

- **Breaking: `checksum="drop"` (`--checksum drop`) drops a corrupt TCP
  segment only; a corrupt UDP datagram is kept**, as under `"ignore"`, and
  still counted under `bad cksum`.  The specification forbids a
  transport-layer stage to withhold content from a stream whose offsets are
  not sequence-anchored (§Discontinuity): a TCP segment left out is a
  sequence hole that its offsets show and its resend fills, but a UDP
  stream's offsets are the payloads that arrived, so a datagram left out
  leaves no trace, and the `bad-checksum` region naming it is declarative
  only.  `0.4.0` dropped both.  Bytes move for a capture with a corrupt UDP
  datagram converted under `drop`: the datagram is now a record, and no
  `bad-checksum` region or skip is written for it.  No fixture has one, so
  no pin moves.  A caller who relied on corrupt datagrams disappearing reads
  `stats.bad_checksum` instead, and finds them in the input.  zipline-kober's
  WireGuard example, whose corrupted tunnel datagrams are UDP, sees them
  decoded as `decrypt-failed` under either policy now.
- **Breaking: a `FlowTracker` writes through a sink, not a session.**  Its
  constructor is `FlowTracker(key, sink, *, options, stats, tick_hz)`: the
  `session`, `decoder`, `writer` and `source` arguments, and the `session`
  attribute, are gone, and a subclass writes its records through
  `self.sink.record(…, origins=…)`, naming the `payload_offset` of every
  packet a record was built from.  That is what lets one tracker convert a
  capture and a `.zpf` alike.  A subclass that called
  `self.session.record(…, decoded=…)` calls `self.sink.record(…)` instead,
  without `decoded`, which the sink supplies.  No capture conversion writes
  a different byte.
- **Breaking: a held segment that the fill covers wholly now flags the
  record covering it `retransmit`**, when the repeat is judged a
  retransmission ([#31](https://github.com/adamkjonsson/python-zipline-wire/issues/31)).
  The shape: a segment arrives ahead of a hole and is held, then the hole is
  filled by a resend that covers the held segment's whole range as well, so
  the sender sent those bytes twice.  The other four sites where a repeat is
  judged always set the flag for a retransmission.  This one discarded the
  bytes, counted and cited them correctly, and set nothing, inherited from
  `0.2.0` rather than decided.  It now flags like the rest; a capture-point
  copy (same TSval, nothing from the peer between) is still a duplicate and
  flags nothing.  Bytes move for a capture with the shape.  None of the 22
  fixtures has it under either overlap policy, so no pin moves and every
  fixture converts to the same bytes.
- **The packeteer floor is `0.16.0`**, up from `0.15.0`, and it now names
  what the *suite* needs as well as the code: `0.16.0`'s generator no longer
  acknowledges past a corrupted segment before its resend
  ([packeteer#163](https://github.com/adamkjonsson/packeteer/issues/163)),
  which the generated `favor-acked` test depends on
  ([#30](https://github.com/adamkjonsson/python-zipline-wire/issues/30)).
- **The python-zipline floor is `0.6.0`**, up from `0.5.0`
  ([#38](https://github.com/adamkjonsson/python-zipline-wire/issues/38)).

### Fixed

- **A sequenced conversion of a direction longer than 2 GiB whose peer only
  acknowledges is written again**
  ([zipline#151](https://github.com/adamkjonsson/zipline/issues/151),
  [python-zipline#75](https://github.com/adamkjonsson/python-zipline/issues/75)).
  An ordinary upload: the server records nothing after its SYN-ACK, whose
  `ack` stays `isn + 1`, and spec `0.21`'s causal check compared it with
  client record ends by serial arithmetic, so from 2 GiB on every record
  read as already acknowledged and `0.4.0` raised `zpf.SemanticError` at the
  writer.  Since `0.22` the comparison is between positions, and the order
  the shape always had is written and verifies on the read-back.  The strict
  `xfail` that stood for it is an ordinary test, and the limit it documented
  is gone from the docs.

### Documentation

- **A guide page, *Converting decoded packets***, on the
  `packets.zpf → inner.zpf` hop: which records are packets, what the output
  says about every input byte, why records join across the input's seams,
  the merge order, and sessions that end and resume.  A new API page for
  `zpfwire.packets`, the sink on the flow page, the `.zpf` input on the
  `convert` CLI page, a *From a `.zpf` of packets* section in the
  specification mapping, and the one limit — a fragmented UDP datagram
  (zipline#166).  `upstream-first.md`'s ledgers gain the issues this release
  filed: packeteer#204; python-zipline#76, #86, #88, #89, #90 and #91;
  zipline#152, #153 and #166.
- **`CLAUDE.md` said the tree writes spec `0.20`**, two versions stale; it
  says `0.23`, and that the input may be a `.zpf` of packets.
- **The release's documentation sweep** found pages still describing a
  capture as the only input, and fixed them.  The overview said everything
  zpfwire writes "sits in one cell" of the two axes.  The mapping said a
  capture-sourced file is "the only kind zpfwire writes", and that nothing
  here produces JSONL.  `architecture.md`'s packet path had no `.zpf` reader
  or sink, and its CLI section counted two refusals.  `testing.md` counted
  460 tests and listed neither new test module, nor the repackaged and
  vendored inputs.  `upstream-first.md` counted twenty-nine issues with two
  open.  The internals module map lacked `packets.py`.  `PacketView.payload_offset`
  and `ConversionStats` described a capture only, and so did the new-transport
  checklist, which now says to write through `self.sink` and name `origins`.
  The README, the converting, filtering, surveying, provenance and ordering
  guides, the CLI index and `limits.md` gained the sentence each lacked
  about a `.zpf` input.

---

## [0.4.0] - 2026-09-19

**The spec `0.21` release.**  Writes spec **v0.21**
(`zpf.SPEC_VERSION == (0, 21)`), up from `0.20`, against packeteer
**0.16.0** and python-zipline **0.5.0**
([#25](https://github.com/adamkjonsson/python-zipline-wire/issues/25),
[#26](https://github.com/adamkjonsson/python-zipline-wire/issues/26)).
The floors are python-zipline `0.5.0`, the first release that implements
`0.21`, and packeteer `0.15.0`, unchanged — nothing in this release touches
packeteer, which is still at `0.16.0`.  The `0.x` rule as before: a `0.20`
reader refuses the files this release writes, and a `0.21` reader refuses
`0.3.0`'s.

**Spec `0.21`** is the design release upstream — two rulings and no option —
and unlike `0.20` it changes what a reader *computes*, in exactly the place
this project ran into in `0.3.0`.  Offsets now **unwrap along stored order**
([zipline#146](https://github.com/adamkjonsson/zipline/issues/146), filed
from [#17](https://github.com/adamkjonsson/python-zipline-wire/issues/17)):
a record's offset is its predecessor's plus the signed serial delta of their
`seq_start`s, so a transport stream is placed at any length and the 2 GiB
ceiling `0.3.0` shimmed around is gone from the format.  A hole of 2³¹ or
more between consecutive records is the one shape the walk cannot place, and
`0.21` states the exit — end the session, open another on the same key with
no `isn` — and names it: the producer SHOULD write **`capture-gap`**
([zipline#147](https://github.com/adamkjonsson/zipline/issues/147), filed
from #17), the word this project chose in `0.3.0`.  And the Participant
Descriptor gains **`adjacency`**, its first body field since `0.15`
([zipline#80](https://github.com/adamkjonsson/zipline/issues/80),
[zipline#106](https://github.com/adamkjonsson/zipline/issues/106)):
`contiguous` or `units`, in the byte that was reserved and zero, so no
existing file changes.  What each of the three means for a file this tree
writes is under its own entry below.  Two `0.21` decisions do not reach a
capture-sourced producer: Package D — deleting `input_extents`,
`reason_class` and the seam predicate — is declined upstream for good, and
nothing here ever depended on it; and the `u64 offset` Record option that
would let one stream span a wide hole is deferred to a `1.x` minor.

### Changed

- **Breaking: a TCP direction longer than 2 GiB is written as one session**
  ([#27](https://github.com/adamkjonsson/python-zipline-wire/issues/27)).
  Spec `0.21` places a transport record by unwrapping along stored order, so
  the ceiling the `0.3.0` shim for zipline#146 worked around is gone from
  the format, and the shim goes with it: `0.3.0` ended the session every
  2 GiB for `offset-limit` and continued the direction in a new one with its
  own origin; the same capture now writes one session whose records sit at
  their true offsets — measured here on five records a GiB apart, the last
  past 2³² from the origin, all placed, nothing unplaceable — and a segment
  reordered across a former boundary lands where it belonged instead of as a
  repeat in the wrong session.  No fixture in `tests/captures/` has the
  shape, so no pin moves; the break is stated for the capture this tree has
  not seen, as `0.3.0` did for PAWS.
- **Breaking: `END_OFFSET_LIMIT` (`"offset-limit"`) and
  `ConversionStats.offset_splits` are removed**, and the summary's `offset`
  line with them.  A caller matching on the reason or reading the counter
  must stop; a `0.3.0` file carrying `offset-limit` is a valid `0.20` file
  that a `0.21` reader would refuse at the version gate anyway.  The
  `capture-gap` split beside it stays — see its entry.
- **Breaking: a sequenced conversion of a direction longer than 2 GiB can
  now be refused when the peer only acknowledges.**  Deleting the shim
  exposed the same 2³¹ ambiguity on the ack axis: the specification's causal
  check compares each record's end against the peer's latest *recorded*
  `ack` by serial arithmetic, a peer that sends pure ACKs writes no record
  after its SYN-ACK, and from 2 GiB on the comparison inverts and
  python-zipline's writer refuses the record as *already acknowledged*.
  Filed as [zipline#151](https://github.com/adamkjonsson/zipline/issues/151)
  and [python-zipline#75](https://github.com/adamkjonsson/python-zipline/issues/75).
  A `0.3.0` conversion of such a capture with `--sequenced` succeeded only
  because the split reset the comparison every 2 GiB; a `0.4.0` one raises
  `zpf.SemanticError` at the writer.  A plain conversion of the same capture
  is one clean session, and a sequenced one whose peer's records carry
  current acks is right at any length.  Not shimmed: `sequenced` is opt-in,
  and a split that hides a rule's ambiguity is what zipline#146 was about.
  The shape is a strict `xfail` in the suite, and flips when the fix lands.
- **`capture-gap` is the specification's word now, and nothing this tree
  writes changes** ([#28](https://github.com/adamkjonsson/python-zipline-wire/issues/28)).
  Spec `0.21` answers [zipline#147](https://github.com/adamkjonsson/zipline/issues/147),
  filed from #17, by naming the exit `0.3.0` already took for a hole of 2³¹
  or more between consecutive records: end the session, open another on the
  same key with no `isn`, and the producer SHOULD write `capture-gap`.
  `END_CAPTURE_GAP` was that value before the format fixed it, so the
  change is a citation — the docstrings and the docs now point at
  §Referencing the source by stream offset rather than deriving the rule
  themselves — and one test for the half of the sentence the suite did not
  check: the follow-on session is on the same key, both participants
  declared, the client's `isn` *not* carried across, and its first record
  at offset `0`.  The `u64 offset` Record option that would let one stream
  span the hole is deferred upstream to a `1.x` minor, which is why a
  converted stream still ends there.
- **`adjacency`: every participant this tree writes is `contiguous`, and no
  byte moves** ([#29](https://github.com/adamkjonsson/python-zipline-wire/issues/29)).
  The Participant Descriptor's reserved `u16` after `participant_id` is
  `adjacency: u8` + `_reserved: u8` since spec `0.21`; `0` is `contiguous`,
  which is what the reserved byte held and meant in every file this project
  ever wrote, so the sixteen decode pins — which hash every Participant
  block's bytes — hold unchanged.  The specification forbids a writer to set
  `units` on a transport-layer participant, and a capture-sourced
  transport-layer file is the only kind zpfwire writes, so `contiguous` is
  the only conformant value; the writer's default supplies it, and a new
  test pins every participant of every fixture to it (and to
  `is_unit_sequence is False` on the reader's layer-aware view).
  `zpf-mapping.md` gains the field, and the one visible consequence: a
  JSONL projection of a zpfwire file now carries `"adjacency":"contiguous"`
  on every participant line.
- **The python-zipline floor is `0.5.0`**, up from `0.4.0`
  ([#26](https://github.com/adamkjonsson/python-zipline-wire/issues/26)).
  No API this tree calls changed shape — `SessionWriter.participant()`
  gained a keyword with a default, and `record()`, `undecoded()`, `Hints`,
  `Decoded` and `RecordFlags` are as they were — so the floor moves for the
  version stamp alone: `0.5.0` is the first release that writes `0.21`.
  For the same input and options every `.zpf` this tree writes differs from
  `0.3.0`'s by the version in the File Header and nothing else, which the
  sixteen decode pins confirm on the first run against the new library.

### Documentation

- `limits.md` no longer describes the 2 GiB split; it states the `0.21`
  rule, and the new `--sequenced` limit beside it.  `upstream-first.md`'s
  *Shims* table is empty for the first time since `0.1.0`, and its ledgers
  gain zipline#146 and python-zipline#70 as resolved and zipline#151 and
  python-zipline#75 as open.
- **A documentation sweep for stale references**, the first of what is now a
  release step.  Most of what it found predated this release: the `0.3.0`
  rules had each fixed the pages their issue named and left the rest —
  `provenance.md`'s reasons table listed three of the seven `Undecoded`
  reasons, `zpf-mapping.md` still said the reassembler could not tell a
  duplicate from a resend and listed the same three reasons, the README's
  flag table offered one overlap policy and its Session End row four
  reasons, the `overlap` summary line was quoted in its pre-`0.3.0` wording
  in three places, `testing.md`'s accounting identities lacked three
  counters and its test count was two releases old, `architecture.md`'s
  session-lifetime table had no `capture-gap`, `writer-mapping.md` named
  three reasons, `reassembly.md`'s `ValueError` sample named one policy, and
  `upstream-first.md` counted twenty-one issues with three open (it is
  twenty-nine with two), still listed packeteer#149 and #150 as open, and
  lacked the five packeteer issues `0.3.0` filed.  All brought current;
  `ordering.md` gains a pointer to the new `--sequenced` limit.
- The README's *what it does not do* list said the reassembler does not yet
  read the TCP Timestamps option, which has been false since `0.3.0`.  The
  bullet is now about what is still true of it: SACK is not read.
- `limits.md` quoted the dependency floors as `packeteer>=0.14.0`,
  `zpf>=0.3.0`, two releases stale; it no longer quotes numbers a test
  cannot see.

---

## [0.3.0] - 2026-09-17

**The TCP Timestamps release.**  The reassembler reads the option for the
first time, and every rule it had to *choose* where the option could *say*
something now says it: whether a repeated segment is a retransmission or the
same transmission seen twice, why a late byte was late, whether a segment is
from after a sequence wrap, and — as a second overlap policy — which copy of
disagreeing bytes the receiver actually kept
([#17](https://github.com/adamkjonsson/python-zipline-wire/issues/17),
[#18](https://github.com/adamkjonsson/python-zipline-wire/issues/18)).
Each rule is measured against real traffic packeteer collected for it —
six captures of real Linux stacks under loss, duplication, corruption,
reordering and a wrap through 2³² — and each is listed below as it lands,
with what it changes in a written file.

Writes spec **v0.20** (`zpf.SPEC_VERSION == (0, 20)`), up from `0.19`,
against packeteer **0.16.0** and python-zipline **0.4.0**.  The floors are
python-zipline `0.4.0`, the first release that implements `0.20`, and
packeteer `0.15.0`, the last thing the code itself needs; the six real
Timestamps captures the release is measured against were collected for it
in packeteer `0.16.0`, and are carried here as fixtures.

### Added

- **The TCP Timestamps option is read to tell a duplicate from a
  retransmission**
  ([#17](https://github.com/adamkjonsson/python-zipline-wire/issues/17),
  item 1).  A repeated segment is a *duplicate* — the same transmission seen
  twice by the capture point, as a mirror port, a two-interface capture or a
  veth pair shows every packet — when it carries the same TSval as the
  transmission it repeats and nothing from the peer arrived between the two.
  It is discarded like any repeat, but cited as `duplicate-discarded`
  (`REASON_DUPLICATE`), counted in the new `ConversionStats.duplicates`
  (segments) and `duplicate_bytes`, and does **not** set `retransmit` on the
  record covering its bytes.  A repeat with a later TSval, or with a peer
  packet between the copies — a fast retransmit is triggered by the peer's
  duplicate ACKs, which is what separates it from a copy on a stack whose
  timestamp tick is coarser than its round trip — is a retransmission, as
  before.  Measured on packeteer's real corpus: the 10 mirror duplicates in
  `tcp_dup_ts.pcap` are all duplicates, and the 36 real resends across
  `tcp_lossy_ts`, `tcp_reorder_ts`, `tcp_corrupt_ts` and `tcp_wrap_ts` are
  all retransmissions, none ambiguous.
- **The option is read to say *why* a late byte was late**
  ([#17](https://github.com/adamkjonsson/python-zipline-wire/issues/17),
  item 3).  A byte arriving inside a gap the reassembler had already given
  up on is compared against the clock of the first segment that overtook
  the gap.  Sent before it — the original, delayed by the network, which a
  wider `reorder_window` or a longer `flush_timeout` would have kept — it is
  cited `late-reordered` (`REASON_LATE_REORDERED`) and counted in the new
  `ConversionStats.late_reordered_bytes`; sent after it — a resend of an
  original that was lost, recovered once the gap had closed, which no policy
  of ours could have kept — it is cited `late-retransmitted`
  (`REASON_LATE_RETRANSMITTED`) and counted in `late_retransmitted_bytes`.
  Inside the same tick as the passer, or without the option, it stays
  `late-arrival` and is counted in `late_bytes` only.  `late_bytes` remains
  the total and `lossless` is unchanged.  The reference is the *first*
  passer at commit time rather than everything committed since, because a
  resend can be slow to arrive too: in `tcp_reorder_ts.pcap` the spurious
  resends take the same slow path as the originals they repeat, and against
  "everything committed" 8 of 10 would read as reordered.  Measured with the
  hold disabled: `tcp_gap_ts.pcap`'s 13 fills are all resends, and
  `tcp_reorder_ts.pcap`'s 18 late regions split 2 reordered, 6 same-tick,
  10 resent — the manifest's own count.
- The summary prints the split beneath `late bytes`, and the CLI's note on a
  lossy conversion now says whether raising the window would have helped:
  it names the reordered bytes when there are any, and says outright that
  no window would have kept them when every late byte was a resend.
- **PAWS**
  ([#17](https://github.com/adamkjonsson/python-zipline-wire/issues/17),
  item 4).  A segment that would contribute bytes but carries a TSval older
  than the last one accepted in order is an old segment from before a
  sequence wrap, and is dropped whole as a receiver drops it (RFC 7323
  §5.3): cited `paws-rejected` (`REASON_PAWS`), counted in the new
  `ConversionStats.paws_bytes`, no flag.  The clock it is compared against
  moves only on in-order arrival — the receiver's own rule — so a delayed
  original that finally fills a hole is not rejected however many newer
  segments passed it, which is what the real receivers in `tcp_reorder_ts`
  and `tcp_wrap_ts` did and D-SACKed.  A repeat of accepted bytes is never
  judged by PAWS.  Measured: the rule fires on none of the six real
  captures under either policy.
- **A segment from the far side of a hole wider than 2³¹ bytes is
  recognised, and opens a new session** (#17, item 4).  Serial arithmetic
  places anything more than 2³¹ away on the near side, so until now such a
  segment was discarded as a retransmission the sender never made and the
  rest of the direction was lost behind it.  A segment further behind than
  the largest window TCP can advertise (2³⁰) whose TSval is newer than the
  last accepted in order is from ahead — but the format stores records in
  serial order, and a record that far past its predecessor *precedes* it,
  so it cannot join the session: the session ends for the new reason
  **`capture-gap`** (`END_CAPTURE_GAP`, beside `fin`/`rst`/`timeout`/
  `capture-end`) and the segment opens the next, exactly as the idle
  timeout splits a flow.  Counted in `ConversionStats.wrap_resolved`.
  Without the option nothing changes.  `FlowTracker` gains a
  `splits_before(pkt)` hook the conversion loop consults beside
  `expired()`; the base answers no.
- **A TCP direction longer than 2 GiB can now be converted** — as several
  sessions, each ending for the new reason **`offset-limit`**
  (`END_OFFSET_LIMIT`) and the next continuing the direction from its first
  byte; `ConversionStats.offset_splits` counts them.  **This is a temporary
  shim** for [zipline#146](https://github.com/adamkjonsson/zipline/issues/146),
  found while measuring item 4: the format places a transport record by
  `seq_start` against the origin with serial arithmetic, which cannot reach
  past 2³¹, so python-zipline's writer refuses the record at 2 GiB and a
  `0.2.0` conversion of any capture carrying more than that in one
  direction — a large download — failed outright.  When the format unwraps
  offsets along stored order the split, the reason and the counter go.  Two
  more findings from the same measurement are filed upstream:
  [zipline#147](https://github.com/adamkjonsson/zipline/issues/147), a hole
  of 2³¹ or more between consecutive records having no representation (which
  is why `capture-gap` above is a split and not a gap), and
  [python-zipline#70](https://github.com/adamkjonsson/python-zipline/issues/70),
  the reader zero-widthing records past 2 GiB on a stream without an `isn`
  while reporting none of them unplaceable.
- **`overlap="favor-acked"`: keep the copy the receiver kept**
  ([#18](https://github.com/adamkjonsson/python-zipline-wire/issues/18)).
  When two copies of a range disagree — a segment corrupted in flight, then
  resent clean — the peer's first acknowledgement covering the range echoes,
  as TSecr, the TSval of the transmission that advanced its window, and
  that copy is written.  The evidence arrives after both copies, so under
  this policy every run is held after it closes until the peer's ack covers
  it; the hold is bounded by `reorder_window` and `flush_timeout`, which
  gain no companion field so `params_digest()` moves only for files that
  choose the policy.  A run the bound releases or the session ends on, a
  range whose copies lacked the option, or an ack that did, are decided as
  `favor-old` and counted in the new `ConversionStats.acked_fallback_bytes`;
  `acked_swaps` counts the ranges where the receiver's choice was not the
  first copy.  Only disagreeing copies are held, so memory is bounded by
  real disagreements.  The record covering a swapped range keeps
  `retransmit` — the sender did resend — and its `timestamp` moves to the
  resend; the loser is cited wherever it lay.  Measured on packeteer's
  `tcp_corrupt_ts.pcap`: five swaps, no fallback, and a stream identical to
  what `checksum="drop"` writes — the receiver's echo and our checksum
  agreeing at every one of the five offsets, from opposite sides.  On the
  other five real captures, where every resend is byte-identical to its
  original, the policy writes the same bytes as `favor-old` with no
  fallback.  `favor-new` stays withdrawn: this is the policy that can be
  honoured, and that one is not.
- **`ConversionStats.ts_fallback`**, a `Counter` of how often a repeat could
  *not* be judged and was treated as a retransmission — the conservative
  reading spec `0.20` asks of a producer that cannot tell — keyed by why:
  `TS_ABSENT` when either side carried no option, `TS_STALE` when the
  transmission it repeated had aged out of the reassembler's memory, which
  is bounded by `reorder_window` bytes (and never emptied, so the copy that
  follows its original is always judged).  Non-zero means some `retransmit`
  flags in the file rest on the fallback rather than on evidence; every
  file written before this release rested on it entirely.
- The summary prints a `duplicates` line — `10 of 154 packets were copies,
  5092 bytes (discarded)` — since a doubled capture is worth one line to the
  user, and a `ts fallback` line when any repeat went unjudged.  The
  `overlap` line now says `retransmitted`.

### Changed

- **Breaking: `retransmit` clears on a duplicated capture.**  A `.zpf`
  written from a capture in which the same transmission appears twice with
  the Timestamps option — a mirror port's file — carries `retransmit` on no
  record that only a copy touched, where `0.2.0` set it on every such
  record; the `Undecoded` blocks for the copies read `duplicate-discarded`
  rather than `overlap-discarded`.  Of the twenty-two fixtures exactly one
  moves, `tcp_dup_ts.pcap` (3 of 7 records flagged → 0); the sixteen that
  predate the Timestamps work are pinned and byte-for-byte unchanged, and
  the five other real Timestamps captures keep every flag they had, since
  every repeat in them is a real resend.  A caller reproducing a `0.2.0`
  file of a mirror capture will see the flag gone and the reason renamed —
  and the file is now what the specification says such a file should be.
  `ReassemblyOptions` gains no field, so `params_digest()` is unchanged; the
  Decoder Descriptor's version is what says the rule moved.
- **Breaking: the `Undecoded` reason on a late byte can now be
  `late-reordered` or `late-retransmitted`** instead of `late-arrival`, on a
  capture that carries the Timestamps option *and* loses bytes to a
  committed gap.  No fixture that predates this release has that shape —
  the two that carry the option lose nothing — so no pinned file moves; a
  `0.2.0` conversion of such a capture, reproduced now, differs in those
  reason strings and nowhere else.  A reader matching on `late-arrival`
  should match on the `late-` prefix, or on all three constants.
- **Breaking: bytes move on a stream carrying the option that PAWS rejects
  or that skips more than 2³¹ bytes.**  Neither shape exists in any fixture
  — the sixteen pins hold, and `tcp_wrap_ts.pcap` under defaults decodes
  identically to before any rule read the option, its wrap being one serial
  arithmetic already crossed — so the break is stated for a capture this
  tree has not seen: a `0.2.0` conversion of one would have written the
  old segment as data, or the far side of the hole as overlap.

**The packeteer floor is `0.15.0`**, up from `0.14.0`.  Nothing at runtime
needs it — the option has been parsed onto every `PacketView` since `0.14.0`
— but `0.15.0` is where the capture-point duplication impairment
(`duplicate_probability`, [packeteer#150](https://github.com/adamkjonsson/packeteer/issues/150))
arrived, and it is the generated half of the material the Timestamps rules
are tested against, so it is the version this release was built on.

**Spec `0.20`.** A repair-and-vector release upstream: no option and no block
was added, no body layout moved, and every `.zpf` this tree writes is
byte-identical to `0.2.0`'s for the same input and options, apart from the
version stamp in the File Header — which is the `0.x` rule: a `0.19` reader
refuses these files, and a `0.20` reader refuses `0.2.0`'s.  The port is the
stamp, the Specification URL, and one definition:

- **`retransmit` names the sender's act, not the reassembler's**
  ([zipline#142](https://github.com/adamkjonsson/zipline/issues/142), filed
  from [#17](https://github.com/adamkjonsson/python-zipline-wire/issues/17)).
  A copy of one transmission — a mirror port, a two-interface capture — is
  not a retransmission and does not set the flag; what the reassembler
  discarded, retransmitted or duplicated, is the `Undecoded` block it always
  was.  This reassembler does not read the TCP Timestamps option and so cannot
  tell the two apart; `0.20` says such a producer SHOULD treat every repeat as
  a retransmission, which is exactly what it did before, so the port itself
  moved no flag.  Leaving the fallback is #17, and it lands in this same
  release — see the **Breaking** entry below, which is where the flag does
  move.
- The other three `0.20` items do not reach a capture-sourced producer: the
  pass-through hole obligation (zipline#133) binds files that cite a `.zpf`
  input, the vector byte repairs (zipline#141) fix files this project never
  vendored, and the manifest's `extents` key (zipline#140) is a suite
  mechanism the siblings consume.

**Python 3.10 is now supported** — `requires-python` is `>=3.10`, down from
`>=3.11` ([#20](https://github.com/adamkjonsson/python-zipline-wire/issues/20)).
Nothing in `zpfwire` itself pinned the floor; it was inherited from `zpf`,
which lowered its own in
[python-zipline#67](https://github.com/adamkjonsson/python-zipline/issues/67).
The one 3.11-ism here was `tomllib` in a test, which now falls back to `tomli`
below 3.11 (a dev-only dependency; the runtime dependencies are unchanged).
CI runs the suite on 3.10 as well.

## [0.2.0] - 2026-09-12

Writes spec **v0.19** (`zpf.SPEC_VERSION == (0, 19)`), against packeteer
**0.14.0** and python-zipline **0.3.0**.

**The packeteer 0.14.0 release**, and a small one: one misfiled skip reason
fixed, one fact the reader can now state up front, one option value withdrawn
because nothing ever read it, and a documentation sweep.  Every `.zpf` this
version writes is byte-identical to `0.1.0`'s for the same input and options.
The TCP Timestamps work ([#17](https://github.com/adamkjonsson/python-zipline-wire/issues/17))
is held for `0.3.0` until a real capture exists to validate it against.

### Added

- **`CaptureReader.link_type_supported`**
  ([#16](https://github.com/adamkjonsson/python-zipline-wire/issues/16)) —
  whether packeteer can decode the capture's link type, asked of
  `packeteer.parse.supports_link_type` once at open (a `--link-type`
  override included) rather than inferred per packet.  When it is `False`
  the reader yields nothing and tallies every packet as
  `unsupported-linktype`, which it always did; what is new is that it can
  say so before reading the first record.

  On the command line, **`zpfwire info` says so up front**, on its own line
  before the table, and **`zpfwire convert` refuses** — exit `1`, "nothing
  to convert" — by the same rule that already refuses `--no-tcp --no-udp`.
  The API still writes the valid, empty file if asked.  packeteer's own
  `UnsupportedLinkTypeWarning` is silenced for exactly that case, since the
  reader has already said it.

### Changed

- **Breaking: `overlap="favor-new"` is withdrawn.**  It was accepted,
  hashed into `params_digest`, documented on the CLI and in the guide — and
  never read: the reassembler has always kept the first copy of any range,
  because a single-pass writer cannot prefer a later copy against bytes it
  has already written, and a rule that held only while a run happened to be
  open would not have been a policy.  `ReassemblyOptions(overlap="favor-new")`
  and `--overlap favor-new` now raise, as any unknown value does.
  **Callers pass `favor-old`, which is what `favor-new` always did**; no
  file's bytes move, and a file already written under `favor-new` carries a
  digest naming a policy that was never applied — which is the reason to
  stop writing more of them.  Any future policy — the copy the peer's
  acknowledgement echoes, say — needs a reassembler that holds runs until
  the choice can be made, and will arrive as a new value of the same field.
- **packeteer floor raised to 0.14.0** (`packeteer>=0.14.0` in
  `pyproject.toml`).  The tree asks `packeteer.parse.supports_link_type`,
  which exists only from that release.  Nothing else in packeteer 0.13.0 or
  0.14.0 reaches this project: the protocol dialect, the front-door
  accessors and the generated-capture changes all sit above the transport
  layer or on the generator side, and every fixture here is byte-identical
  to packeteer's at `v0.14.0`.

### Fixed

- **A raw-IP packet whose IP header did not parse was skipped as
  `unsupported-linktype`** ([#16](https://github.com/adamkjonsson/python-zipline-wire/issues/16),
  from [packeteer#138](https://github.com/adamkjonsson/packeteer/issues/138)).
  `LINKTYPE_RAW` has no link-layer header, so such a packet arrives with no
  header object of any kind — the same shape as an unknown link layer, which
  is what the old inference read it as.  It is now `malformed-ip-header`:
  the link type itself announced IP, so the failure is above the link layer,
  exactly as for an Ethernet frame with an IP EtherType and no IP header.
  The skip ladder is told whether the capture is headerless, because nothing
  on the packet can say.  Only the reason's name moves; no `.zpf` written
  for any capture packeteer already decoded changes.

### Documentation

- A sweep of every page against what the tree does after `0.1.0`.  Two
  passages were wrong rather than stale: the provenance guide and the
  reassembler internals both placed the handshake record "at the initial
  sequence number", where it has sat at `isn + 1` — the stream origin,
  shared with the first data record — since the python-zipline#63 fix, and
  the guide's gap walk still told readers to skip the SYN record to avoid a
  phantom one-byte gap that no longer occurs.  The accounting identity in
  four places predated `checksum="drop"` and omitted
  `checksum_dropped_bytes`; the specification mapping's `ack` row said "as
  last seen" where `0.1.0` made it the serial maximum over contributing
  packets, and lacked the handshake record, the Source comment and the
  `bad-checksum` reason.  The rest is drift: the read-back assertion is two
  lists since spec `0.19`; the fixture and test-file tables gained the
  entries added since; the upstream ledger now lists all twenty-one issues
  this project has filed, with the three open ones named as what `0.3.0`
  waits on; and the pointers to `plans/PLAN.md` as a live document now go to
  the release plans and `limits.md`, which are.
- `limits.md` states what the TCP Timestamps option could settle and why
  reading it is held ([#17](https://github.com/adamkjonsson/python-zipline-wire/issues/17)),
  and ties the one-policy `overlap` option to the deferred `favor-acked`
  design ([#18](https://github.com/adamkjonsson/python-zipline-wire/issues/18)).

## [0.1.0] - 2026-09-07

Writes spec **v0.19** (`zpf.SPEC_VERSION == (0, 19)`), against packeteer
**0.12.0** and python-zipline **0.3.0**.

**The first release**, so everything the project does is listed here rather
than what changed since a previous one.

### Added

- **`zpfwire convert` — a capture becomes a `.zpf`** — the headline
  deliverable, as a Python API (`capture_to_zpf`, `convert`) with a CLI on
  top.  The output is a **capture-sourced, transport-layer** file: the
  top-left cell of the specification's provenance/layer table, which is the
  one fact that settles most of the encoding decisions.

  The capture is declared as the file's source with its SHA-256 digest, so a
  consumer can confirm a `.zpf` still matches what it came from.

- **The file says who built it and when** — `creator`, `produced_by` and
  `produced_at` on the File Header.  Since spec `0.19` this is a file's whole
  account of itself: a `SEQUENCED` session no longer records what its order
  rests on, the producer being trusted for the basis exactly as it already was
  for the order, so build provenance is what a consumer has to go on.

  `produced_at` is the only part of the output that is **not** a function of
  the input, so two conversions of one capture otherwise differ by nothing but
  those bytes.  `capture_to_zpf(..., produced_at=...)` takes `"now"` (the
  default), an `int` of Unix seconds or a `datetime` to pin it, or `None` to
  leave it off.  The command line has no flag for it — a caller who needs a
  pinned stamp is scripting the conversion — so a CLI conversion is not
  byte-reproducible.  The reproducibility of the *decode* is a separate thing
  and rests on the decoder's `params_digest`, which is a function of the
  options alone.

- **TCP reassembly, with the policy written into the file** — segments in,
  runs of stream bytes out, as one session per conversation and two
  participants per session.  Out-of-order segments are held in an explicit
  reorder buffer, retransmits are trimmed against what was already accepted,
  and each direction's records are stored in ascending `seq_start` as the
  specification requires.

  The policy is `ReassemblyOptions` — `reorder_window`, `flush_timeout`,
  `overlap`, `session_timeout`, `coalesce` — and it is not tuning: the
  specification makes committing a gap irreversible, so these settings decide
  which bytes reach the output.  That is why they are hashed into a
  `params_digest` on the Decoder Descriptor, which is what makes a conversion
  reproducible and tells a later reader why bytes are missing.

- **UDP conversations** — a datagram is already the unit the application sent,
  so each becomes one record carrying `MESSAGE`, with no sequence numbers and
  no reassembly.  Fragmented datagrams are reassembled at the IP layer first,
  so a fragment is never mistaken for a whole packet.

- **Nothing is lost quietly** — `ConversionStats` accounts for every packet
  and every payload byte: converted, skipped by reason, filtered, or
  discarded with a count against it.  Bytes that exist in the capture and
  reach no record — a discarded retransmit, a late arrival — are written as
  `Undecoded` blocks naming their byte range in the capture file, which is
  the only thing in the format that can express them.  A gap gets no block: a
  hole is barred against a capture source, and `seq_start` already carries
  the extent of what is missing.

- **Every link type packeteer reads** — Ethernet, Linux cooked capture v1 and
  v2, raw IP, and BSD loopback (`DLT_NULL` / `DLT_LOOP`), the framing
  `tcpdump -i lo0` writes on macOS and the BSDs.  Loopback came with packeteer
  0.12.0 ([packeteer#124](https://github.com/adamkjonsson/packeteer/issues/124))
  and needed nothing here: the packets arrive already decoded.  A link type
  neither sibling knows is skipped and counted as `unsupported-linktype`
  rather than mistaken for a packet carrying only bytes.

- **A capture cut short says so** — a capture taken with `tcpdump -s` holds
  less of each packet than crossed the wire, so payloads past the limit reach
  a record short, and nothing in a payload distinguishes that from a short
  payload the sender chose.  `ConversionStats.truncated` counts the packets it
  happened to, `CaptureReader.snaplen` and `PacketView.truncated` expose it per
  capture and per packet, and the capture's snaplen is recorded on the Source
  Descriptor beside the link type.  A TCP stream shows the loss a second way,
  as the gap the next sequence number leaves; **a UDP datagram shows it nowhere
  else at all**, which is what makes the count worth writing.

- **`--sequenced`** — store each TCP session in a valid causal linearization
  and mark it `SEQUENCED`, rather than in capture order.  A TCP session is
  *hint-ful*, so the order follows from `seq` and `ack` with no guesswork.
  Off by default: a causal order needs both directions in hand, so the
  session is buffered until it ends, which is unbounded for its lifetime in a
  format whose point is streaming.  UDP sessions are deliberately not marked.

- **`zpfwire info`** — report the conversations a capture holds, and what a
  conversion would produce, without writing anything.  `zpfwire.survey()` is
  the same thing from Python.

- **Filtering** — `--proto`, `--port`, `--src-port`, `--dst-port`, `--src`,
  `--dst` and `--host`, with CIDR ranges, IPv6 and `!` negation.  The
  semantics are packeteer's `PacketFilter` rather than a second dialect of
  the same flags; `zpfwire.filter` is the adapter.

- **`--jsonl`** — write the JSON-Lines projection instead of the binary
  container, for reading a conversion with ordinary text tools.

- **`--checksum {ignore,drop}` and `ReassemblyOptions.checksum`**
  ([#7](https://github.com/adamkjonsson/python-zipline-wire/issues/7)) — what
  to do with a packet whose transport checksum does not verify.

  It corrects a fidelity bug in what the tool writes.  A corrupt segment is
  normally retransmitted cleanly and the damaged copy arrives *first*, so
  `favor-old` kept the bytes no endpoint ever accepted and cited the good
  retransmission as an overlap discard — eleven times over in the corpus's
  `payload_corruption.pcap`, and silently, since the file reads back with no
  diagnostics either way.  `"drop"` discards such a packet whole, the way a
  receiver does: the checksum failed, so the header is not to be trusted
  either, its flags open and close nothing, and it never starts a session.
  The payload is cited as an `Undecoded` block with reason `bad-checksum`.

  The default is **`"ignore"`**, which is the previous behaviour, because
  checksum offload makes a capture taken on a sending host report wrong
  checksums for traffic that was correct on the wire; dropping those by
  default would gut such a capture.  Bad checksums are counted under either
  policy, so a conversion that keeps them still says how many there were.

  Two things are deliberately not read as failures: an IPv4 UDP datagram
  whose checksum is `0`, which means *none was computed* (RFC 768), and any
  packet from a capture a snaplen truncated, whose checksum covers bytes that
  were not kept and so can be compared against nothing.  Both are decided
  here, the second from `ParsedPacket.datagram_truncated`: packeteer 0.9.1
  cleared such a checksum ([packeteer#92](https://github.com/adamkjonsson/packeteer/issues/92))
  and 0.12.0 records it again, since rebuilding the packet as truncated needs
  the captured value ([packeteer#126](https://github.com/adamkjonsson/packeteer/issues/126)).

  The knob lives on `ReassemblyOptions` rather than being a bare CLI flag
  because it decides which bytes reach the output, so it has to be inside
  `params_digest()`.

- **`zpfwire.cite_undecoded()`** — the `Undecoded`-writing rules as a function
  rather than only a `FlowTracker` method, so a stage that discards a packet
  before it reaches a session can still cite it.

### Fixed

- **The handshake record sits at the stream origin, not at the `isn`.**  The
  SYN consumes a sequence number without delivering a byte, so the origin is
  `isn + 1` and a record at the `isn` is one below it — an offset of `-1` in a
  space that has none.  The subtraction is modular, so nothing reported the
  error: it absorbed it, placing the record at offset 4294967295 and making
  every stream with an observed handshake measure 4294967295 bytes however far
  its data actually ran.  Spec `0.16` already gave this shape in prose; `0.17`
  promotes it to a MUST, states what a reader does with a violating record
  (accept the file, treat the record as unplaceable at zero width, report), and
  carries the shape this wrote as its negative vector,
  `advisory-seq-start-below-origin`.

  The corrected record shares its `seq_start` with the first data record, which
  is what the origin being `isn + 1` means; the two are stored in the order
  they were produced, and the ordering rule is satisfied by the SYN coming
  first.

- **A coalesced record's timestamps are the extremes over its contributing
  packets, not the last one appended.**  A segment held out of order arrives
  *before* the segment that fills the hole below it and is appended *after*
  it, so taking the last append's time dated the unit complete a step before
  its final packet arrived — and left `ts_first`, taken from the earlier
  append, *after* `timestamp`, a record that started after it finished.
  `timestamp` is now the last contributing packet in capture order and
  `ts_first` the first, which is the per-unit reading spec `0.17` states
  explicitly.

- **A coalesced record's `ack` is the serial maximum over its contributing
  packets** ([#11](https://github.com/adamkjonsson/python-zipline-wire/issues/11)),
  on the same rule as the two stamps beside it.  It came from whichever packet
  was appended last, which is not a rule: for a drained run that is the
  *earlier* packet, so a record reported a timestamp and an acknowledgement
  taken from two different packets.

  Acks are cumulative, so one observed on any contributor is still true when
  the run completes, and the maximum is the strongest statement the run can
  make that is certainly true.  Understating one is sound — a lower bound
  yields no false edges — but it is a lost edge rather than a harmless one:
  under `--sequenced` the linearization releases a record once every peer
  record it acknowledges has been emitted, so the same conversation could
  sequence differently for a reason that was not in the capture.

  The `ACK` flag is deliberately **not** consulted here.  A data segment always
  has something to acknowledge whatever its flags say; the one place the flag
  is read is the handshake record, whose opening `SYN` genuinely has nothing to
  acknowledge yet.

### Documentation

- A Sphinx site under `docs/`: an introduction, task guides for converting,
  reassembly policy, provenance, causal order and surveying, a CLI reference,
  the API reference, and an `internals/` section on how the pieces fit.
  `sphinx-build -W` is clean.
- `README.md` covering install, the two commands, and what the output is.
- Three HTTP captures added to the fixture corpus in `tests/captures/`, which
  every test sweeps: each must convert to a file `zpf.open` reads with no
  diagnostics and nothing unplaceable.

---

[Unreleased]: https://github.com/adamkjonsson/python-zipline-wire/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/adamkjonsson/python-zipline-wire/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/adamkjonsson/python-zipline-wire/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/adamkjonsson/python-zipline-wire/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/adamkjonsson/python-zipline-wire/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/adamkjonsson/python-zipline-wire/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/adamkjonsson/python-zipline-wire/releases/tag/v0.1.0
