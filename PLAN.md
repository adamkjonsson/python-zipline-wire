# zpfwire — captures → .zpf

## Context

This repo (currently `python-zipline-decode`) is empty: LICENSE, a one-line
README, one commit. Its purpose is to be the glue between **network protocol
decoding** and the **Zipline Payload Format**:

- **packeteer** (`/Users/adam/projs/packeteer`, v0.8.0) reads captures and parses
  packets. Pure stdlib, no runtime dependencies.
- **python-zipline** (`/Users/adam/projs/python-zipline`) reads and writes `.zpf`
  files against **spec v0.16**. Distribution and import name are both **`zpf`**
  (the PyPI name `zipline` belongs to an unrelated project).

Neither knows about the other, so today there is no way to get from a capture to
a `.zpf` at all — every `.zpf` in existence is a hand-built conformance vector.
This project closes that gap and gives the format a supply of real-world input.

The headline deliverable is **pcap → `.zpf` with TCP reassembly**, as a Python
API with a CLI on top.

### Decisions taken

| Question | Decision |
|---|---|
| Name | **`python-zipline-wire`**, import/CLI/dist `zpfwire`. Replaces `zipline-decode`/`zpfdecode`: in `zpf`, "decoder" already means *a stage deriving one `.zpf` from another*, so "decode" in the project name collides with the format's own vocabulary. `zpfwire` names the boundary actually crossed — wire to payload. |
| v1 scope | TCP reassembly only — one capture-sourced, transport-layer `.zpf`. No application decoders. |
| Transports | TCP **and** UDP. Everything else is skipped and counted. |
| Reassembler | Lives **here**, not in packeteer (rationale below). |
| Dependencies | Editable installs of local siblings `../packeteer` and `../python-zipline`. |
| Ruff | `ruff.toml` copied verbatim from packeteer, as requested. |

The repo and directory rename (`python-zipline-decode` → `python-zipline-wire`,
locally and on GitHub) is yours to make; the plan below writes code under
`src/zpfwire/` either way.

## Working practice: upstream-first

One purpose of this project is to **pressure-test packeteer and python-zipline**,
so gaps found here get fixed *there*, not papered over here.

- Every defect or missing capability found in either sibling gets a **GitHub
  issue filed in that repo** (`gh issue create`), including improvement ideas —
  not only outright bugs.
- Any local shim is **temporary**: it carries a comment linking the upstream
  issue, and it is deleted when the fix lands.
- This goes in `CLAUDE.md` as a standing rule.

**Issues filed at the start** (all identified before a line of code was written):

*packeteer* — [#61](https://github.com/adamkjonsson/packeteer/issues/61),
[#62](https://github.com/adamkjonsson/packeteer/issues/62),
[#63](https://github.com/adamkjonsson/packeteer/issues/63),
[#64](https://github.com/adamkjonsson/packeteer/issues/64),
[#65](https://github.com/adamkjonsson/packeteer/issues/65),
[#66](https://github.com/adamkjonsson/packeteer/issues/66).
**All six are implemented in packeteer 0.8.0**, which is not yet tagged — that
repo closes issues at release, not at merge, so they still read OPEN.

1. **[#61] Payload silently destroyed on well-known ports.** `_try_parse_dns` /
   `_try_parse_dhcp` / `_try_parse_http` ran unconditionally and returned `b""`
   on success, so `ParsedPacket.payload` was empty for every packet on
   80/8080/53/5353/67/68 with no opt-out. Was **the one blocking gap**.
   *Landed:* `parse_packet(data, *, link_type=…, decode_app=True)` and the same
   keyword on `parse_pcap_packet` / `parse_pcap_file`. Propagates through
   tunnels; tunnel decoders still run.
2. **[#62] No streaming pcap iterator.** `read_pcap` materialised a `list`.
   *Landed:* `packeteer.pcap.open_pcap(path=…|file_object=…)` → `PcapReader`, a
   context-managed iterator of `PcapRecord(data, ts_sec, ts_frac, offset,
   data_offset, orig_len)`. `data_offset` is what capture-scoped provenance
   needs; `orig_len` reveals snaplen truncation.
3. **[#63] TCP options never parsed.** *Landed:* `parse/tcp.py` decodes MSS,
   window scale, SACK permitted, SACK blocks and timestamps into the existing
   `TCPOptions`, plus a new `unknown` list of `(kind, value)` pairs.
4. **[#64] pcapng timestamp resolution collapsed to a bool.** *Landed:*
   `PcapFileHeader.tick_hz` carries the real rate, `nanoseconds` becomes a
   derived view, and `ts_frac` is now expressed in `tick_hz` units.
   `TimestampResolutionWarning` fires when a spec cannot express the source.
5. **[#65] No IP defragmentation.** *Landed:* `packeteer.parse.defragment` /
   `defragment_ipv4` / `defragment_ipv6`, frames in and frames out, over the
   stateful `Defragmenter` (`feed`, `flush`, `incomplete`). Also fixed a real
   defect: non-first fragments used to be parsed as though they carried a
   transport header, fabricating ports out of user data — they now have
   `transport = None`.
6. **[#66] IP length not exposed.** *Landed:* `IPHeader.total_length` and
   `IPv6Header.payload_length`, and the parser now trims Ethernet padding out
   of `payload` itself.

**Filed after reviewing 0.8.0** — both are needed by phase 5, and both are
consequences of the above landing rather than defects in it:

- **[#71] `ParsedPacket` carries no payload offset.** `open_pcap` gives a byte
  offset for the *record*; turning that into an offset for the *payload* needs
  the payload's position within the frame, which the walk computes and discards.
  `len(frame) - len(payload)` is not a substitute — #66's padding trim makes the
  payload a non-suffix on padded frames, so the arithmetic is silently short.
- **[#72] `Defragmenter` reports nothing about which fragments composed a
  datagram.** The failure path has `IncompleteDatagram`; the success path
  returns bare frames, so a reassembled datagram cannot be traced back to the
  records — and therefore to the file offsets — it came from.

*python-zipline* — [#47](https://github.com/adamkjonsson/python-zipline/issues/47), [#48](https://github.com/adamkjonsson/python-zipline/issues/48), [#49](https://github.com/adamkjonsson/python-zipline/issues/49). All three still open; 0.8.0 was packeteer-only.

1. **[#47] `ts_first` unreachable from the ergonomic writer.** `SessionWriter.record()`
   has no `ts_first=` keyword. **Not a blocker:** the predicted workaround —
   `FileWriter.write_block(zpf.Record(session_id=…, sender_pid=…, source_id=…,
   ts_first=…))` — is confirmed to write and read back with `diagnostics == []`.
   An ergonomics gap, not a capability gap.
2. **[#48] Stale spec URL.** `pyproject.toml` `[project.urls] Specification` points at
   v0.12 while the code implements 0.16.
3. **[#49] `DECODER_API.md` checklist item 6** (causal output ordering + conditional
   `sequenced=`) is unimplemented. **Not a blocker for phase 6 either:** the
   primitives that phase reuses, `zpf.causal_merge` and `zpf.verify_sequenced`,
   both exist today. #49 is about the library's own decoder helpers.

## What the spec demands of this writer

From `/Users/adam/projs/zipline/docs/zipline-payload-format.md` (v0.16). Our
output sits in the **top-left cell** of the spec's two-axes table:
*capture-sourced* provenance, *transport* layer. That fixes almost everything.

The canonical shape already exists as a conformance vector —
`/Users/adam/projs/python-zipline/tests/vectors/reassembler-declared/` — and it
is exactly a capture→zpf tool's output. Read it before writing code.

- **File Header** — `tick_hz` = `1_000_000` (µs) or `1_000_000_000` (ns pcapng);
  `creator = "zpfwire <version>"`; `single_clock=True` (one capture file is one
  tap, so timestamps are globally comparable — honest, and it lets a later stage
  soundly sequence regrouped one-way streams). `produced_by` is *permitted* on a
  capture-sourced file (only *required* once a `zpf-input` source appears); set it.
- **Source** — `kind="capture"`, `uri` = capture path, `digest="sha256:…"`,
  `link_type` = the pcap LINKTYPE.
- **Decoder** — `add_decoder("tcp-reassembly", output_layer=OutputLayer.TRANSPORT,
  version=…, params_digest=…)`. The spec makes this a **SHOULD** for a
  head-of-pipeline reassembler, and we take it: it is *the only place our overlap
  policy and timeouts can be recorded*, which is what makes the decode
  reproducible. Records then carry `decoder=`.
- **Session** — one per flow. `proto="tcp"|"udp"`, `key="a:port <-> b:port"`.
  `sequenced` stays False in v1 (see phase 6).
- **Participant** — two per session, `endpoint="ip:port"` (bracketed IPv6).
  TCP: `isn` **MUST** be present when the handshake was observed and **MUST** be
  omitted otherwise; `tcp_role=INITIATOR/RESPONDER` when known.
- **Record** — `seq_start` (absolute wire seq of the first payload byte) and
  `ack` for TCP; `RecordFlags.MESSAGE` for UDP datagrams; `PSH/FIN/RST/URG` as
  seen; `RETRANSMIT` when overlap was resolved inside the record.
  - **`content_type` MUST be omitted** — forbidden at the transport layer, and
    the writer raises on it.
  - **`spans` MUST be empty** — the checker requires every `Span` to reference a
    `zpf-input` source, and ours is a capture.
  - **Timestamp rule**: the time of the **last** packet contributing bytes, not
    the first. A retransmit contributing no accepted bytes does not move it.
- **Session End** — `reason` ∈ `fin` / `rst` / `timeout` / `capture-end`.

**Two writer rules that shape the reassembler's design, not just its output:**

1. *Per-participant `seq_start` ordering is a MUST*, enforced at
   `conformance.py:794` with serial arithmetic (32-bit wrap is legal).
2. *Committing a gap is irreversible.* Having emitted a record past missing
   bytes, we **MUST NOT** emit those bytes if they turn up later — they are
   dropped.

Together these mean the reassembler needs an explicit **reorder buffer with a
bounded flush policy**, and that the policy is a user-visible knob rather than an
implementation detail: it decides what data gets thrown away.

**Not applicable here** (so nobody reaches for them): `Discontinuity` is
*decoded-layer only* — a TCP hole needs no marker, since absolute `seq_start`
values make it visible by arithmetic. `spans`-based derivation belongs to a
decode stage, which v1 does not have.

**We do not need to re-implement spec validation.** `FileWriter._emit`
([writer.py:596](/Users/adam/projs/python-zipline/src/zpf/writer.py)) runs
`ConformanceChecker.observe(block)` *before* bytes reach the sink, so a violation
raises `zpf.SemanticError` at the offending call.

## Why the reassembler lives here

packeteer has no reassembly at all — zero hits for `reassembl*` across its source
tree; `packeteer stream` and `generate/session.py` are *generation*-only, and
`parse/info.py:_session_key` builds a directional 5-tuple only to count it. So
this is greenfield either way, and it could plausibly go upstream.

It stays here because packeteer is a **stateless per-packet** toolkit, while
reassembly's output shape is dictated by zipline: byte runs rather than segments,
`timestamp` = last contributing packet, irreversible gap commitment, ascending
`seq_start` per participant. Those are zipline's writer rules, and moving them
into packeteer would import format semantics into a format-agnostic library.

What reassembly *consumes* is genuinely packeteer's job, and that is where the
upstream issues above are aimed: undecoded payload, streaming iteration with byte
offsets, TCP options, defragmentation, IP length.

## Design

```
src/zpfwire/
  __init__.py     public API re-exports
  __main__.py     CLI — argparse, thin
  capture.py      capture → PacketView stream (the packeteer seam)
  flow.py         canonical flow keys, session/participant identity
  tcp.py          TCP reassembler — the substance
  udp.py          UDP datagram flows
  convert.py      orchestration: PacketViews → zpf writer calls
  options.py      ReassemblyOptions + params_digest
  py.typed
tests/
  captures/       fixtures copied from packeteer/testcases/
```

### `capture.py` — the packeteer seam

Originally the one place a shim was unavoidable: `parse_pcap_packet` destroyed
the payload on exactly the ports a payload format exists to serve, so this
module walked the layers itself with packeteer's per-layer parsers
(`packet_parser(data) -> (header_size, next_layer_id, header)`), slicing by the
reported header sizes and reading the IP length from raw bytes to strip padding.

**packeteer 0.8.0 retires that shim.** `parse_packet(data, link_type=…,
decode_app=False)` was checked against the hand-walk across every fixture —
946 payload-bearing packets, byte-for-byte identical results, zero differences.
The rewrite deletes the dispatch, the raw-bytes IP-length read (#66 trims
padding upstream now) and `tick_hz_for` (#64 supplies `header.tick_hz`, and
`ts_frac` already arrives in those units, so `_frac_scale` goes too).

Three things the rewrite must keep or gain:

- **The fragment check stays.** #65 fixed *non-first* fragments to report
  `transport = None`, but a *first* fragment still parses a transport header
  with only that fragment's payload behind it. On `fragmentation.pcap` that is
  59 packets which `parse_packet` will happily hand over truncated. Either
  defragment ahead of the parse (phase 7) or keep skipping on
  `ip.flags & MF` / non-zero `fragment_offset` (IPv4) and `ip.fragment` (IPv6).
- **Link types broaden for free.** The hand-walk understood Ethernet and RAW
  only. `parse_packet` adds SLL/SLL2, ARP, MPLS, PPPoE and the tunnel stack
  (VXLAN, GENEVE, GTP-U, GRE, EtherIP, IP-in-IP, AH, ESP) — traffic that
  currently lands in the `unsupported-linktype` and `non-ip` skip tallies.
  Decide deliberately whether a tunnelled flow keys on the inner or outer
  addresses; the plan's answer is inner, since that is the stream that has a
  payload.
- **Header offsets are lost.** The hand-walk knew where the payload sat in the
  frame; `parse_packet` does not report it (#71). Phase 5 needs it, so either
  that issue lands first or `capture.py` keeps a reduced walk for offsets alone.

Streaming replaces the whole-file read: `open_pcap` yields one `PcapRecord` at
a time, so `CaptureReader` stops materialising `capture.packets` and carries
`offset` / `data_offset` / `orig_len` through to the `PacketView`.

Output is a frozen `PacketView`: `ts_ticks`, `src`/`dst`, `proto`, `src_port`,
`dst_port`, `seq`, `ack`, `tcp_flags`, `payload: bytes`, `packet_num` — plus,
after the rewrite, the record's byte offsets and the parsed `TCPOptions` (#63)
that SACK-aware loss inference needs.

### `flow.py`

`FlowKey` = `(proto, endpoint_a, endpoint_b)` with the endpoints **sorted** so
both directions land in one session — the canonicalisation `_session_key`
deliberately does not do. Participant id 0/1 in first-seen order.

Participants are declared lazily on the first packet from that direction, which
always precedes any record from it, so `isn` is known by declaration time when
the SYN was captured and correctly absent when it was not. Single pass.

### `tcp.py` — the reassembler

Per direction: `isn`, `tcp_role`, `next_seq`, a reorder buffer keyed by sequence
number, and the run being accumulated.

Per segment: drop pure duplicates; trim bytes already committed and set
`RETRANSMIT` on the resulting record; buffer anything ahead of `next_seq`; emit
contiguous runs in ascending `seq_start`.

**Record granularity.** Both "one record per segment" and "coalesce contiguous
bytes into runs" are conformant byte runs. Default to **coalescing**, flushed on
PSH / gap / FIN / RST / timeout / end of capture, with `--no-coalesce` available.
`timestamp` is the last contributing packet's time, per the spec rule.

**Gap policy** (`options.py`, hashed into the decoder's `params_digest`):
`overlap` (`favor-old` default), `reorder_window` bytes, `flush_timeout`,
`session_timeout`. When window or timeout forces a commit past missing bytes, the
gap is permanent and later arrivals are dropped and counted.

### `convert.py`

`capture_to_zpf(source, sink, *, options=…) -> ConversionStats` — hash the
capture, derive `tick_hz` from `PcapFileHeader.nanoseconds`, create the writer,
declare source and decoder, drive flows. `ConversionStats` reports packets read /
skipped (by reason, including fragments), sessions, records, payload bytes, gaps
committed, late bytes dropped.

`session.record(...)` defaults `source=` only when exactly one source is
declared; we declare exactly one, so it can be omitted.

### CLI

Mirror packeteer's shape exactly: single `__main__.py`, `_cmd_<name>(args)`
handlers, all parsers built in `main()`, `set_defaults(func=…)`, two-line
dispatch, `print(f"Error: {e}", file=sys.stderr); sys.exit(1)`. Keep it lean —
all logic in the library.

```
zpfwire convert capture.pcap -o out.zpf
    --jsonl                          # zpf.create(face="jsonl")
    --no-udp / --no-tcp
    --overlap {favor-old,favor-new}  --reorder-window N
    --flush-timeout S  --session-timeout S  --no-coalesce
    --proto/--port/--src/--dst/--host
zpfwire info capture.pcap            # preview the flows that would become sessions
```

**Reuse `packeteer.filter.PacketFilter`** rather than writing filtering again —
it already does CIDR, IPv6 and `!` negation with validated semantics. It matches
against the packet-spec *dict*, but only reads `network.protocol/src/dst` and
`transport.src_port/dst_port`, so a small dict built from a `PacketView`
satisfies it. Mirror `_build_packet_filter`
([`__main__.py:797`](/Users/adam/projs/packeteer/src/packeteer/__main__.py)).

### Scaffolding

`pyproject.toml` (setuptools, `src/` layout, `requires-python = ">=3.11"` — the
floor `zpf` sets — `[project.scripts] zpfwire = "zpfwire.__main__:main"`,
`dependencies = ["zpf", "packeteer"]`); `ruff.toml` **copied verbatim from
packeteer**; `requirements.txt` with `-e ../packeteer`, `-e ../python-zipline`,
pytest, ruff, build; `CLAUDE.md` following the siblings' structure plus the
upstream-first rule; `.github/workflows/ci.yml` modelled on packeteer's (ruff job
+ pytest matrix, 3.11–3.14); `.gitignore`; ship `py.typed` (as `zpf` does).

## Phasing

- [x] **0.** Scaffolding, venv, CI; upstream issues filed.
- [x] **1.** `capture.py` + `PacketView` + layer walk, with tests.
- [x] **2.** `flow.py` + `udp.py` + `convert.py` → a valid UDP-only `.zpf` end to
  end. Deliberately first: it proved the writer wiring against the smallest
  possible model before the TCP state machine landed on top.
- [x] **3.** `tcp.py` — the reassembler.
- [x] **4.** CLI + filtering (`__main__.py`, `filter.py`, `survey.py`).
- [x] **8.** README.
- [ ] **4b.** Adopt packeteer 0.8.0: rewrite `capture.py` onto
  `parse_packet(decode_app=False)` + `open_pcap`, drop `tick_hz_for` and the
  raw-bytes length read, carry byte offsets and `TCPOptions` on `PacketView`.
  Prerequisite for 5 and 7, and the point at which the shim comment goes.
- [ ] **5.** Capture-scoped provenance: overlap-discard `Undecoded` markers,
  handshake SYN records, `ts_first`. Byte offsets now exist (packeteer#62);
  `FileWriter.undecoded(source, session_id, pid, off_start, off_end, …)` is the
  vehicle and is already in `zpf`. Remaining gap is locating the payload within
  the frame — packeteer#71, or a reduced local walk.
- [ ] **6.** Sequenced TCP sessions (below). **Never blocked** — `causal_merge`
  and `verify_sequenced` ship in `zpf` today.
- [ ] **7.** IP reassembly (below). **Unblocked by packeteer#65.**

**Built so far** — `src/zpfwire/`: `capture.py`, `flow.py`, `tcp.py`, `udp.py`,
`convert.py`, `options.py`, `stats.py`, `filter.py`, `survey.py`, `__main__.py`.
138 tests, ruff clean. Every fixture in `tests/captures/` converts to a file
that `zpf.open` reads with no diagnostics and `zpf validate --strict` accepts.

Two design points settled during implementation, both worth keeping:

- **Pure ACKs produce no records.** The spec permits zero-length ack-only
  records, but they would multiply file size for information that only matters
  once sessions are `SEQUENCED`. Revisit in phase 6.
- **A FIN on its own segment does not get a record.** When a FIN rides along
  with data the record carries the flag; when it arrives alone, the direction's
  close is carried by the Session End reason instead of an empty record.

### Phase 6 — sequenced sessions

A TCP session is *hint-ful*, so `SEQUENCED` needs no `sequenced_basis`;
correctness comes entirely from storing records in a valid causal linearization
rather than capture order. Reuse `zpf.causal_merge` and `zpf.verify_sequenced`
(`order.py`) — do not reimplement RFC 1982 arithmetic or the merge.

The real tension is with streaming: a causal order needs both directions
available, so a sequenced writer buffers a session until its end. Make it opt-in
(`--sequenced`), bound the per-session buffer, and document the trade-off.
Verify against the spec's skewed two-file worked example and `verify_sequenced`.
Relates to python-zipline issue 3.

### Phase 7 — IP reassembly

Defragmentation belonged upstream (packeteer#65), as the counterpart to the
existing `fragment_ipv4`/`fragment_ipv6`, and **it landed in 0.8.0**. `zpfwire`
currently counts and skips fragmented packets, reporting them in
`ConversionStats` — visible, not silent — and that skip counter now goes to zero.

Measured on `tests/captures/fragmentation.pcap`: 287 frames in, 148 passed
through untouched and 59 reassembled, 0 incomplete, against the 139 packets
`zpfwire` skips as `ip-fragment` today.

`Defragmenter` is the primitive to use rather than the `defragment()` wrapper,
because `feed(frame, ts)` is what composes with a streaming reader — feed each
`PcapRecord`, parse whatever comes back. A returned frame that is the fed frame
itself is a passthrough; anything else is a reassembled datagram, whose
timestamp is the completing fragment's, which is exactly the spec's
last-contributing-packet rule.

Two things to settle when building it:

- **Provenance is unavailable** for reassembled datagrams (packeteer#72): the
  contributing records, and therefore their file offsets, are not recoverable.
  Until that lands, phase 5 markers cover unfragmented traffic only, and a
  reassembled datagram's `packet_num` is the completing fragment's.
- **`Defragmenter.incomplete`** carries `IncompleteDatagram` records with a
  `reason` of `timeout` / `overlap` / `too_large` / `evicted`. Fold those into
  `ConversionStats` so dropped datagrams stay as visible as skipped ones are
  now, and surface the buffer caps (`max_datagram_bytes`, `max_buffered_bytes`)
  and `timeout_s` through `ReassemblyOptions` into `params_digest`, since they
  decide what gets thrown away — the same argument that made the TCP gap policy
  a user-visible knob.

## Verification

**Unit** — synthesize captures in memory with packeteer's own `PacketBuilder` /
`generate_tcp_stream` + `write_pcap` into `io.BytesIO`, which is how packeteer
tests itself and gives exact control over retransmits, reordering and loss.

**Integration** — packeteer ships ready-made captures at
`/Users/adam/projs/packeteer/testcases/` that are *not referenced by any of its
tests* and are almost purpose-built for this project: `retransmission.pcap`,
`packet_loss.pcap`, `delay.pcap` (reordering), `payload_corruption.pcap`,
`sudden_termination_{1,2}.pcap` (RST), `stray_1.pcap`, `no_errors.pcap`,
`udp.pcap`, `http_example.pcapng`, `dns_example.pcapng`, `fragmentation.pcap`.
Copy them into `tests/captures/`.

**The assertion that matters** — every produced file must read back clean:

```python
with zpf.open(out_path) as f:
    for session in f.sessions():
        list(session.records())
    assert f.diagnostics == []
```

Plus: reassembled bytes equal the expected application payload (especially on
`http_example.pcapng`, which is exactly where `parse_packet` would have silently
emptied the payload); `retransmission.pcap` yields the same stream as
`no_errors.pcap`; `packet_loss.pcap` produces a visible `seq_start` gap and a
non-zero gap count; RST captures end their session with `reason="rst"`;
`fragmentation.pcap` reports skipped fragments until phase 7.

**Golden** — `zpf.binary_to_jsonl` gives a diffable projection; keep one small
golden JSONL and compare against the `reassembler-declared` vector's shape.

**Style** — native pytest (matching python-zipline, the newer sibling) in a
top-level `tests/`; `ruff check src/ tests/` must be silent.

**End to end** — `python -m zpfwire convert tests/captures/http_example.pcapng -o
out.zpf`, then `zpf validate --strict out.zpf` and `zpf cat out.zpf` from the
sibling's CLI.

## Known limitations to record, not solve now

Each has an upstream issue above; none is worked around permanently here.

**Resolved by packeteer 0.8.0** — struck once phase 4b adopts it:

- ~~Whole-file read until a streaming iterator exists~~ — `open_pcap` (#62).
- ~~No overlap-discard provenance until byte offsets are available~~ —
  `PcapRecord.data_offset` (#62). Locating the payload within the frame is the
  one piece still missing (#71).
- ~~pcapng resolutions other than µs/ns misread~~ — `tick_hz` (#64). Keep
  `--tick-hz` as an override, not a necessity.
- ~~No SACK-aware loss inference while TCP options go unparsed~~ — `TCPOptions`
  is populated on the parse path (#63).
- ~~Fragmented packets skipped~~ — `Defragmenter` (#65), phase 7.

**Still open:**

- `ts_first` reaches the file only through `write_block(zpf.Record(…))` until
  python-zipline#47 lands. Confirmed working, just not ergonomic.
- No capture-scoped provenance for reassembled datagrams (packeteer#72), so
  phase 5 markers cover unfragmented traffic only.
- Payload byte offsets need packeteer#71 or a reduced local layer walk.

**Housekeeping:** the venv has been rebuilt against packeteer 0.8.0.dev0, and
all 138 tests still pass unchanged — 0.8.0 is backwards-compatible with the
current `capture.py`, because the hand-walk drives the per-layer parsers rather
than `parse_packet`. Phase 4b is therefore a deliberate migration, not a repair.
