# Upstream-first

One purpose of this project is to **pressure-test packeteer and
python-zipline**.  Gaps found here get fixed *there*, not papered over here.

This is a working rule with teeth, not an aspiration, and it has changed both
siblings substantially.

## The rule

- Every defect or missing capability found in either sibling gets a **GitHub
  issue filed in that repo** — improvement ideas count, not just outright
  bugs.  Ask the maintainer before filing, then file.
- Any local shim is **temporary**.  It carries a comment naming the upstream
  issue, and it is deleted when the fix lands.
- The release plan in `plans/` tracks the known gaps and which phase depends
  on them; {doc}`../reference/limits` states them for users.

The reason it is worth the friction: a workaround here hides the problem from
every *other* consumer of that library.  Filing it fixes it once.

## What it produced

Forty-eight issues so far, and two are open:
- packeteer#231, its name being taken on PyPI, which this tree meets
  meanwhile by declaring packeteer by its release tag;
- packeteer#232, a fragmented generated stream that does not reproduce from
  its seed.

Every other one has been answered upstream and released, most of them
within days.

**packeteer**, filed before a line of code was written:

| Issue | Gap | Resolution |
|-------|-----|-----------|
| #61 | The parser destroyed the payload on well-known ports with no opt-out | `decode_app=False` |
| #62 | No streaming reader, and no per-record byte offsets | `open_pcap` → `PcapReader` |
| #63 | TCP options never decoded on the parse path | `TCPOptions` populated |
| #64 | pcapng `if_tsresol` collapsed to a bool | `PcapFileHeader.tick_hz` |
| #65 | No IP defragmentation | `defragment` / `Defragmenter` |
| #66 | IP length not exposed, so padding could not be trimmed | `total_length`, and the parser trims |

**packeteer**, filed after reviewing the fixes:

| Issue | Gap | Resolution |
|-------|-----|-----------|
| #71 | `ParsedPacket` carried no payload offset, so #62 and #66 did not compose | `payload_offset` |
| #72 | `Defragmenter` reported nothing about which fragments composed a datagram | `AssembledFrame.tokens` |
| #76 | `iter_packets` exposed neither the capture header nor what reassembly dropped | `PacketReader` |

**packeteer**, filed while using it:

| Issue | Gap | Resolution |
|-------|-----|-----------|
| #92 | A snaplen-truncated packet kept its checksum, so a truncated capture read as corruption throughout | Cleared on truncation (0.9.1); reinstated with `datagram_truncated` beside it (0.12.0) |
| #94 | Nothing said a packet *was* truncated, so a cleared checksum was ambiguous | `ParsedPacket.datagram_truncated`, `PcapRecord.orig_len` |
| #138 | No way to ask whether a link type is supported, so it was inferred from missing headers — and a raw-IP packet with a bad IP header was misfiled | `supports_link_type`, `SUPPORTED_LINK_TYPES` (0.14.0) |
| #149 | No real capture, here or in packeteer's corpus, of a retransmission carrying the TCP Timestamps option | `tcp_lossy_ts.pcap` and `tcp_dup_ts.pcap`, real Linux stacks under loss and mirror duplication (0.15.0) |
| #150 | The generator rebuilds every resend with a fresh TSval, so it cannot produce a capture-point duplicate | `duplicate_probability`, the capture-point duplication impairment (0.15.0) |
| #158 | No receiver-side capture, so no real file in which a hole is actually *in* the capture rather than absorbed by the sender's retransmission | `tcp_gap_ts.pcap` and `tcp_reorder_ts.pcap` (0.16.0) |
| #160 | No real capture in which two copies of a range *differ* — a segment corrupted in flight, then resent clean | `tcp_corrupt_ts.pcap`, delivered the day it was filed (0.16.0) |
| #161 | No real capture of a stream whose sequence numbers pass through 2³² | `tcp_wrap_ts.pcap`, delivered the day it was filed (0.16.0) |
| #163 | The generated receiver acknowledged past a corrupted segment before its retransmission, so a generated stream could not test a policy that reads acks | Fixed the same day (0.16.0); reviewed here across 20 seeds |
| #164 | A generated retransmission kept the original's acknowledgement number, so a direction's acks stepped backwards on every resend after peer data | Fixed the same day (0.16.0); reviewed here across 20 seeds × four impairments |
| #204 | `write_pcap` and `write_pcapng` annotated their records as a `list` though they stream any iterable, so a typed export had to materialise every packet | `Iterable[PacketTuple]`, a consumed-once contract and its tests (0.18.0) |
| #213 | Checksum verification looped in Python once per 16-bit word, the largest single cost of reading a capture, found by profiling this tree | The internet checksum computed in C (0.20.0): `iter_packets` 39% faster on `http_stream_1.pcap`, every output byte-identical, confirmed here on `.dev1` |
| #227 | With data both ways, a corrupted segment was rebuilt with a fresh checksum over its damaged payload, so it verified: half the fidelity tool's two-way corruption runs had to be voided | The byte flipped after the rebuild (0.21.0); reviewed here on `.dev1`: only those segments' bytes move, over 20 seeds per case, and no run is void |
| #228 | A stray never carried the Timestamps option, so an RFC 7323 §3.2 receiver — this tree's `require_timestamps` — dropped every one and was never tested by them | `stray_timestamps`, stamping each stray as the side it impersonates (0.21.0); reviewed here on `.dev1`, and it found #61 here |
| #231 | The distribution name `packeteer` is taken on PyPI by an unrelated project, so a dependency declared by name and range can be satisfied by anyone who uploads a version inside it | **Open** — this tree declares packeteer by its release tag meanwhile (0.8.0) |
| #232 | A fragmented generated stream does not reproduce from its seed: `fragment_ipv4` draws the IP ID from the unseeded global `random`, so a duplicated fragmented datagram also gets a fresh ID | **Open** — found building the UDP fidelity ledger, which groups fragments by label and does not depend on IDs; the reproduction test's fragmented case is a strict `xfail`.  A comment asks for seeded, non-zero IDs that a duplicate repeats, so the fidelity sweep can score the `copy` flag (0.9.0) |

**python-zipline**:

| Issue | Gap | Resolution |
|-------|-----|-----------|
| #47 | `ts_first` unreachable from the ergonomic writer | `record(ts_first=…)` |
| #48 | Specification URL pointed at a stale version | Held to `SPEC_VERSION` by a test |
| #49 | No writer-side support for causal output ordering | `begin_session(linearize=True)` and a write-time order guard |
| #63 | A zero-length SYN record at the `isn` sat one below the stream origin, and `check_coverage` measured the stream as 2³²−1 bytes | The writer refuses a `syn` record whose `seq_start` is not `isn + 1`, and `FileReader.unplaceable` reports what the offset space cannot place (0.3.0) |
| #70 | On a stream with no `isn`, records past 2 GiB were given zero-width ranges while none was reported unplaceable — the reader's two answers disagreed | `0.4.0` applied the origin floor without an `isn`; `0.5.0`'s unwrapping walk places them (spec `0.21`) |
| #75 | `verify_sequenced` and the linearize guard refuse a valid linearization past 2 GiB when the peer's last recorded `ack` is stale — a pure-ACK peer's is its SYN-ACK's | `0.6.0`: an ack is a position, unwrapped along its sender's records into the peer's offset space (spec `0.22`); `verify_sequenced` takes each participant's `isn`.  The strict `xfail` here became an ordinary test (0.5.0) |
| #76 | No sessionization stage that fans out: `decode_stage` mirrors its input one to one, so the decrypted-tunnel hop had only the primitive writer API | `sessionize_stage` (0.6.0), which this tree's `.zpf` input is built on |
| #86 | `FlowSession.record` took no `ts_first`, and going around it through `flow.writer` skipped the stage's coverage | `ts_first=` on the stage's record, derived with `ts` when both are omitted (0.6.0) |
| #88 | `sessionize_stage` returns the *ended* session for a key used before, so a flow that resumes after a timeout or past a `capture-gap` cannot open its second | `session(key)` opens a new session once the key's last one has ended (0.6.0); the two strict `xfail`s here became tests |
| #89 | `sessionize_stage` and `decode_stage` take no `face` or `creator`, so a stage writes binary only | `face=` and `creator=` on both stages (0.6.0); `--jsonl` works for a `.zpf` input, and its File Header names `zpfwire` |
| #90 | `check_splice` reports a transport record with `seq_start` crossing an input Discontinuity, which spec `0.22` permits | A transport record carrying `seq_start` is not checked (0.6.0); the strict `xfail` here became a test, and the differential checks both input shapes |
| #91 | `FlowSession.end` re-reads the whole input to measure `input_extents`, once per output session — quadratic under fan-out | Each input stream's extent and gaps are measured once per stage and kept (0.6.0): `http_stream_1.pcap`'s 20 flows convert in 1.4 s, down from 5.2 s |
| #101 | Writing a record costs about 10 µs whatever its size — option encoding, block validation, `Flag`-enum arithmetic and the checker — and storing pure ACKs (0.6.0) doubled the records a conversion writes | 45% cheaper, with no byte moved (0.8.0): `http_stream_1.pcap` converts in 146 ms, down from 166 |
| #102 | The distribution name `zpf` is taken on PyPI by an unrelated project, as packeteer#231 | Distributed as `python-zipline`, imported as `zpf` still (0.8.0); this tree still declares it by tag, since it is not on PyPI (0.9.0) |

**zipline** (the specification):

| Issue | Gap | Resolution |
|-------|-----|-----------|
| #142 | The `retransmit` flag's "retransmission/overlap" carries two readings — the sender resent, or the reassembler discarded — and a duplicated capture tells them apart | Spec `0.20`: the flag names the sender's act; a producer that cannot tell a copy from a resend SHOULD treat it as one, which is what this tree did until `0.3.0` read the option (#17) |
| #146 | A transport record was placed against the origin by serial arithmetic, so a stream stopped at 2 GiB: an ordinary large download could not be represented | Spec `0.21`: offsets unwrap along stored order — each record's is its predecessor's plus the signed serial delta — and a stream is placed at any length.  The shim this tree carried for one release is gone (0.4.0) |
| #147 | A hole of 2³¹ or more between consecutive records of one participant had no representation and no name — the far side reads as *before* the near side | Spec `0.21`: no representation, by design — the pair is an ordering violation by construction — and the exit this tree already took is now the standard: end the session, open another on the same key with no `isn`, and the producer SHOULD write `capture-gap`.  The `u64 offset` option is held for a `1.x` minor |
| #151 | The causal edge rule compares a record's end against a peer record's `ack` with serial arithmetic, and the two can be a whole stream apart when the peer only sends pure ACKs; #146's shape on the ack axis | Spec `0.22`: an ack's position is the previous ack's plus the signed serial delta, the first measured from the peer's origin, and the edge compares plain integers.  Found by deleting the #146 shim; `--sequenced` converts the shape again (0.5.0) |
| #152 | The no-splice duty offered two recourses, a Discontinuity or a `units` output, and a transport output may use neither — so a reassembler over a unit sequence could never coalesce two packets | Spec `0.22`: a transport output whose records carry `seq_start` meets both duties through its offsets, and MAY cite across input units or an input Discontinuity |
| #153 | No format-level type for one network packet: a packet-preserving stage had only a decoder-private `dec:` token, which a generic sessionizer could match only by convention | Spec `0.22`: the `net:` scheme, `net:ip` and `net:ethernet`, meaning what `LINKTYPE_RAW` and `LINKTYPE_ETHERNET` mean |
| #166 | A fragmented UDP datagram over a unit-sequence input has no conformant record: `0.22`'s permission is keyed on `seq_start`, and fragment offsets prove the join as sequence numbers do | Spec `0.24`: a record flagged `message` may cite several input units, or cross a declared break.  Measured here in 0.8.0 as the only difference between a capture and a `.zpf` of the same packets; since 0.9.0 the datagram is written, and the two paths agree on every run |
| #168 | A pure ACK stored after a FIN sits one past the FIN's number, so the stream's extent counts that number, which no record covers; stored on the FIN's own number instead, it stalls the causal merge | Spec `0.24`: the extent counts sequence numbers, and a FIN's position is owed nothing.  The ACK stays at its wire number here; the stricter reader found a hole `stats.gaps` did not count (#76, 0.9.0) |
| #169 | A transport stage may not withhold content from a stream without sequence numbers, so a datagram the capture point saw twice must be written twice, and no flag or block can say the second is a copy | Spec `0.24`: the `copy` flag.  Set here when zpfwire can tell: the same frames under the same non-zero IP identification (#77, 0.9.0) |

Two of packeteer's fixes went further than asked — #73 added `iter_packets`
in response to the composition problem, and #76 put the tick rate on the
timestamp itself.

## How to file a good one

The issues above share a shape, and it is worth copying:

1. **Say where it was found.**  "Found while building zpfwire, a capture →
   Zipline Payload Format converter."  Context tells the maintainer what the
   API is being asked to do.
2. **State the problem in terms of the library**, not your workaround.
3. **State the consequence concretely**, with numbers where you have them.
   "946 payload-bearing packets across 13 captures" is checkable; "this is
   important" is not.
4. **Suggest a fix, and name what it costs.**  Note breaking changes.
5. **Say what you will do meanwhile**, so nobody thinks you are blocked.

The most useful ones explain why the obvious workaround does *not* work.
#71's argument was that `len(frame) - len(payload)` looks like a substitute
for a payload offset and silently is not, once #66 trims padding — that is the
part a maintainer cannot be expected to notice.  #138's was that the inference
from missing headers *looks* right on every link type but one, and that one
has no headers to be missing.

A gap in test material is an issue too.  packeteer#149 asked for a capture,
not a feature: the rule it would validate was sound on paper and unverified on
any real stack, and filing that is what kept the rule from shipping on paper
alone — five of the seven packeteer issues from `0.3.0` were captures, and
every rule in that release is measured against one.

## Verify, do not trust the changelog

Every upstream fix in this project was checked against the real fixtures
before the plan was updated: `iter_packets` was diffed byte-for-byte against
the hand-rolled walk across all 13 captures, and `payload_offset` was verified
by slicing the capture file at the computed offsets and comparing.

That is not distrust; it is that a changelog states intent and a fixture
states behaviour.  Two of the findings in this project — the mixed-tick-rate
case and the empty-session basis problem — were only visible by running the
thing.

## Shims

None, right now.  The last one — a TCP direction split into a new session
every 2 GiB, because the format placed a record against the origin by serial
arithmetic and so could not reach past 2³¹ — waited on
[zipline#146](https://github.com/adamkjonsson/zipline/issues/146) through
`0.3.0` and was deleted in `0.4.0` when spec `0.21` unwrapped offsets along
stored order.  Deleting it exposed
[zipline#151](https://github.com/adamkjonsson/zipline/issues/151), the same
ambiguity on the ack axis, which the split had been hiding.  That one was
**not** shimmed — for one release it was a documented limit of `--sequenced`
and a strict `xfail`, because a split that hides a rule's ambiguity is what
#146 was about — and spec `0.22` answered it, so `0.5.0` turned the `xfail`
into an ordinary test.

A shim looks like this: a comment naming the issue, and a note in the
current release plan under `plans/` saying which phase is waiting.  When the
fix lands, the shim is deleted in the same commit that records the version
bump.

{doc}`capture-seam` is the worked example of a shim's whole lifecycle — five
workarounds in one module, all now gone.
