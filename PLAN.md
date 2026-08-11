# zpfwire — captures → .zpf

## Context

This repo (currently `python-zipline-decode`) is empty: LICENSE, a one-line
README, one commit. Its purpose is to be the glue between **network protocol
decoding** and the **Zipline Payload Format**:

- **packeteer** (`/Users/adam/projs/packeteer`, v0.7.0) reads captures and parses
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
[#66](https://github.com/adamkjonsson/packeteer/issues/66)

1. **[#61] Payload silently destroyed on well-known ports.** `_try_parse_dns` /
   `_try_parse_dhcp` / `_try_parse_http`
   ([parse/core.py:382-384](/Users/adam/projs/packeteer/src/packeteer/parse/core.py))
   run unconditionally and return `b""` on success, so `ParsedPacket.payload` is
   empty for every packet on 80/8080/53/5353/67/68 with no opt-out. Information
   loss with no way to decline it. Ask: `decode_app: bool = True` on
   `parse_packet`/`parse_pcap_packet`. **This is the one blocking gap** — see
   `capture.py` below.
2. **[#62] No streaming pcap iterator.** `read_pcap` materialises a `list`; the
   private machinery already streams (`max_packets` via `_ChainedReader`). Ask:
   public `iter_pcap()` yielding records **plus each record's byte offset in the
   file** — the offset is what capture-scoped provenance needs.
3. **[#63] TCP options never parsed.** `parse/tcp.py` skips them; `TCPHeader.options`
   is always `None` from a parse, losing SACK, timestamps and window scale.
4. **[#64] pcapng timestamp resolution collapsed to a bool.** `if_tsresol` becomes
   `nanoseconds: bool`, so any resolution that is not 1e9 is treated as
   microseconds and silently misread.
5. **[#65] No IP defragmentation** — the missing counterpart to the existing
   `fragment_ipv4` / `fragment_ipv6`.
6. **[#66] IP length not exposed.** Parsed `IPHeader` carries no `total_length` (nor
   IPv6 payload length), so callers cannot trim Ethernet padding without
   re-reading raw bytes.

*python-zipline* — [#47](https://github.com/adamkjonsson/python-zipline/issues/47), [#48](https://github.com/adamkjonsson/python-zipline/issues/48), [#49](https://github.com/adamkjonsson/python-zipline/issues/49)

1. **[#47] `ts_first` unreachable from the ergonomic writer.** `SessionWriter.record()`
   has no `ts_first=` keyword; it needs `write_block(zpf.Record(...))`.
2. **[#48] Stale spec URL.** `pyproject.toml` `[project.urls] Specification` points at
   v0.12 while the code implements 0.16.
3. **[#49] `DECODER_API.md` checklist item 6** (causal output ordering + conditional
   `sequenced=`) is unimplemented — directly relevant to phase 6 below.

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

### `capture.py` — the one place a shim is unavoidable

The obvious call is `packeteer.parse.parse_pcap_packet`, and packeteer issue 1
above makes it unusable: payload is destroyed on exactly the ports a payload
format exists to serve. The real fix is upstream (`decode_app=False`).

**Interim, until that lands:** walk the layers here using packeteer's per-layer
parsers, which all share one signature —
`packet_parser(data) -> (header_size, next_layer_id, header)` — and give exact
header sizes: `ethernet` → `vlan`\* → `ip` → `tcp` | `udp`, slicing by
`header_size` at each step. This reuses packeteer's actual parsing rather than
duplicating it; only the dispatch is ours. It is ~40 lines, carries a comment
linking the issue, and collapses to a single `parse_packet(..., decode_app=False)`
call when the fix ships.

Two details this layer owns for now, both with upstream issues filed (6 and 3):

- **Trim to the IP length**, read from raw bytes, or Ethernet padding on short
  frames gets reassembled as payload.
- **TCP options are unavailable**, so no SACK-aware loss inference. `data_offset`
  is honoured, so payload slicing is correct.

Output is a frozen `PacketView`: `ts_ticks`, `src`/`dst`, `proto`, `src_port`,
`dst_port`, `seq`, `ack`, `tcp_flags`, `payload: bytes`, `packet_num`.

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
- [ ] **5.** Capture-scoped provenance: overlap-discard `Undecoded` markers,
  handshake SYN records, `ts_first`. Gated on packeteer#62 (byte offsets) and
  python-zipline#47.
- [ ] **6.** Sequenced TCP sessions (below).
- [ ] **7.** IP reassembly (below).

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

Defragmentation belongs upstream (packeteer issue 5), as the counterpart to the
existing `fragment_ipv4`/`fragment_ipv6`. Until it lands, `zpfwire` counts and
skips fragmented packets and reports them in `ConversionStats` — visible, not
silent. When it lands, `capture.py` consumes it and the skip counter goes to
zero.

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

- Whole-file read until `iter_pcap()` exists — not memory-bounded on huge
  captures, awkward for a format whose selling point is streaming.
- No overlap-discard provenance until byte offsets are available.
- `ts_first` omitted until the writer keyword exists.
- pcapng resolutions other than µs/ns misread; add a `--tick-hz` override and
  document it.
- No SACK-aware loss inference while TCP options go unparsed.
