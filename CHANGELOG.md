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

[Unreleased]: https://github.com/adamkjonsson/python-zipline-wire/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/adamkjonsson/python-zipline-wire/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/adamkjonsson/python-zipline-wire/releases/tag/v0.1.0
