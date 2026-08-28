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

Writes spec **v0.16** (`zpf.SPEC_VERSION == (0, 16)`), against packeteer
**0.9.1** and python-zipline **0.2.0**.

**Nothing has been released yet**, so everything the project does is listed
here; `0.1.0` will be the first tag.

### Added

- **`zpfwire convert` — a capture becomes a `.zpf`** — the headline
  deliverable, as a Python API (`capture_to_zpf`, `convert`) with a CLI on
  top.  The output is a **capture-sourced, transport-layer** file: the
  top-left cell of the specification's provenance/layer table, which is the
  one fact that settles most of the encoding decisions.

  The capture is declared as the file's source with its SHA-256 digest, so a
  consumer can confirm a `.zpf` still matches what it came from, and the file
  is stamped `SINGLE_CLOCK` — one capture is one tap, so every timestamp in
  it was taken against one clock.

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
  were not kept.  The first is decided here; the second is the parser's, which
  clears a checksum it cannot compare since packeteer 0.9.1
  ([packeteer#92](https://github.com/adamkjonsson/packeteer/issues/92)).

  The knob lives on `ReassemblyOptions` rather than being a bare CLI flag
  because it decides which bytes reach the output, so it has to be inside
  `params_digest()`.

- **`zpfwire.cite_undecoded()`** — the `Undecoded`-writing rules as a function
  rather than only a `FlowTracker` method, so a stage that discards a packet
  before it reaches a session can still cite it.

### Documentation

- A Sphinx site under `docs/`: an introduction, task guides for converting,
  reassembly policy, provenance, causal order and surveying, a CLI reference,
  the API reference, and an `internals/` section on how the pieces fit.
  `sphinx-build -W` is clean.
- `README.md` covering install, the two commands, and what the output is.
- Three HTTP captures added to the fixture corpus in `tests/captures/`, which
  every test sweeps: each must convert to a file `zpf.open` reads with no
  diagnostics.

---

<!-- No release has been tagged yet, so there is nothing to compare against;
     this becomes a compare link at 0.1.0. -->

[Unreleased]: https://github.com/adamkjonsson/python-zipline-wire/commits/main
