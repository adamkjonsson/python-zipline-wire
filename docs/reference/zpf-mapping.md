# Specification mapping

What each of zpfwire's objects becomes in the written file, field by field.
Everything here follows from one fact: the output is **transport-layer**.  It
is **capture-sourced** when the input is a capture, which is what most of this
page describes; when the input is a `.zpf` of packets it is **zpf-sourced**,
and {ref}`zpf-sourced` says what changes.  Where a field is absent, the rule
that forbids it is named — an absent field in this format is usually a
statement, not an omission.

The specification is `zipline-payload-format`, version `zpf.SPEC_VERSION`.

## File Header

| Field | Value | Why |
|-------|-------|-----|
| `tick_hz` | The capture's rate | Read from the file header, and each packet rescaled into it. A pcapng states resolution per interface, so two packets in one file need not share a unit, while a `.zpf` carries exactly one. |
| `creator` | `zpfwire <version>` | |
| `produced_by` | `zpfwire <version>` | *Permitted* on a capture-sourced file — only *required* once a `zpf-input` source appears. Set anyway. |
| `produced_at` | The conversion's wall-clock time | Build provenance is where the forensic account of a file lives since spec `0.19`. It is also the only part of the output that is not a function of the input: pass `produced_at=` an `int` or `datetime` to pin it and get byte-identical conversions, or `None` to leave it off. |

## Source Descriptor

Exactly one, so records may omit `source=` and be attributed to it.

| Field | Value |
|-------|-------|
| `kind` | `capture` |
| `uri` | The capture's path, or absent for an unnamed stream |
| `digest` | `sha256:…` of the capture's bytes |
| `link_type` | The pcap LINKTYPE from the file header |
| `comment` | `snaplen=N` when the capture states a limit, absent otherwise — provenance of the same kind as the link type, and what explains payloads shorter than what was sent. The descriptor has no field for it; a field of its own would be a specification change |

The digest is the dependency edge: it is how a consumer confirms the `.zpf`
still matches the capture it came from.

## Decoder Descriptor

| Field | Value |
|-------|-------|
| `name` | `tcp-reassembly` (`DECODER_NAME`) |
| `output_layer` | `TRANSPORT` |
| `version` | The zpfwire version |
| `params_digest` | `sha256:…` of the {class}`~zpfwire.options.ReassemblyOptions` |

Declaring a head-of-pipeline reassembler is a **should**, and zpfwire takes
it: this is the only place the overlap and gap policy can be recorded, which
is what makes a conversion reproducible.  Records then carry `decoder=`.

Note that declaring a decoder does **not** imply a decoded layer.  The
`output_layer` stays `TRANSPORT`; reassembly is a stage, not a dissection.

## Session

One per conversation, both directions.

| Field | Value |
|-------|-------|
| `proto` | `tcp` or `udp` |
| `key` | `a:port <-> b:port`, endpoints sorted so direction does not matter |
| `sequenced` | `False` unless `sequenced=True` was asked for, and then only for TCP — a bare assertion since spec `0.19`, see {doc}`../guide/ordering` |

## Participant

Two per session, declared lazily on the first packet from that direction —
which always precedes any record from it.

| Field | Value |
|-------|-------|
| `endpoint` | `ip:port`, IPv6 bracketed |
| `isn` | The initial sequence number — present **exactly when** the handshake was observed, and absent otherwise |
| `tcp_role` | `INITIATOR` or `RESPONDER` when the handshake said which |
| `adjacency` | **`contiguous`**, always — the writer's default, never named.  A body field since spec `0.21`; see below |

The `isn` rule is a **must** in both directions: present when known, absent
when not.  This is why participant declaration is lazy rather than done up
front — the SYN has to have been seen first.

`adjacency` is the Participant Descriptor's first body field since `0.15`:
`contiguous` means stored neighbours join, which is what every file ever
written meant; `units` declares a *unit sequence*, a decoded participant no
two of whose adjacent records may be assumed to join — the wholesale form of
a Discontinuity at every seam, for a stage that reorders a participant's
records or a decoder whose units decompose one another (nested DNS, in
[zipline#106](https://github.com/adamkjonsson/zipline/issues/106)).  On a
transport-layer participant the field says nothing, since the offsets come
from sequence numbers, and **a writer MUST NOT set `units` there**.  A
capture-sourced, transport-layer file is the only kind zpfwire writes, so
`contiguous` is the only conformant value, and a test pins every participant
of every fixture to it.  Dissection, when it comes, is the first layer at
which the field could say something.

One visible consequence: **every participant line in a JSONL projection of a
zpfwire file carries `"adjacency":"contiguous"`**, right after `"pid"`, as a
body field always projects; a line without it is rejected.  Nothing in this
tree produces or compares JSONL, but that is where the line's shape is
looked up.

The far endpoint is declared even if it never sent anything.  The conversation
had two ends whether or not both spoke; a session naming only the talker would
describe the capture rather than the connection.

## Record

One per run of contiguous stream bytes, or one per datagram for UDP.

| Field | Value |
|-------|-------|
| `timestamp` | The time of the **last** packet contributing bytes — the moment the run became complete |
| `ts_first` | The first contributing packet's time, when the run coalesced more than one |
| `payload` | The stream bytes |
| `seq_start` | The absolute wire sequence number of the first payload byte (TCP) |
| `ack` | The serial **maximum** of the acknowledgement numbers on the packets that contributed bytes (TCP) — acks are cumulative, so it is the strongest statement the run can make that is certainly true |
| `flags` | `PSH` / `FIN` / `RST` / `URG` as seen; `RETRANSMIT` when the sender resent bytes of the record's range — see below; `MESSAGE` for a UDP datagram |
| `decoder` | The reassembly decoder |

One record is not a byte run: the **handshake record**, written once per
direction when its SYN was captured.

| Field | Value |
|-------|-------|
| `payload` | Empty |
| `seq_start` | `isn + 1` — the stream origin, shared with the first data record, and **not** the `isn`, which sits one below the origin in a space with no negative offsets |
| `ack` | The SYN's own, when its `ACK` flag was set; absent on the opening SYN, which has nothing yet to acknowledge |
| `flags` | `SYN` |
| `timestamp` | When the connection opened — the one time nothing else in the file records |

The timestamp rule is the specification's, not a choice: a retransmit
contributing no accepted bytes does not move it, because an acknowledgement
can never precede arrival of what it acknowledges.

`RETRANSMIT` is defined by the specification as the **sender's** act: the
sender resent bytes of the record's range.  A copy of one transmission — a
mirror port, a two-interface capture — is not a retransmission and does not
set it.  The reassembler tells the two apart by the TCP Timestamps option
(since `0.3.0`, [#17](https://github.com/adamkjonsson/python-zipline-wire/issues/17)):
a repeat with the same TSval as the transmission it repeats and nothing from
the peer between the two is a duplicate, cited `duplicate-discarded` and
setting no flag; any other repeat is a retransmission, and sets the flag on
whichever record was accumulating when it was discarded.  When the option is
absent, or the original has aged out of the reassembler's memory, the
specification's fallback for a producer that cannot tell applies — every
repeat is a retransmission — and `stats.ts_fallback` counts that it did.
What was discarded is cited either way, as an `Undecoded` block naming the
bytes in the capture — see {doc}`../guide/provenance` and
{doc}`../guide/reassembly`.

### Fields deliberately absent

| Field | Why |
|-------|-----|
| `content_type` | **Forbidden** at the transport layer — a byte run has no media type. The writer raises on it. |
| `spans` | Every span must reference a `zpf-input` source, and a capture is not one. This is why `ts_first` exists. A `.zpf` input's records carry them — see {ref}`zpf-sourced`. |

## Undecoded

Written for bytes that are in the capture and reached no record.

| Field | Value |
|-------|-------|
| `source_id` | The capture source |
| `session_id`, `participant_id` | **`0`** — against a capture source there is no input `.zpf`, so there is no id namespace to name |
| `off_start`, `off_end` | Byte offsets **into the capture file**, half-open |
| `reason` | `overlap-discarded` or `duplicate-discarded` for a repeat; `late-arrival`, `late-reordered` or `late-retransmitted` for a byte inside a committed gap; `paws-rejected`; `bad-checksum` under `checksum="drop"` — see {doc}`../api/flow` |
| `reason_class` | `bytes` |
| `decoder_id` | The reassembly decoder |

Only the **bytes-exist** class may be declared against a capture source.  A
hole-class region — a gap — must not be, and needs no block: a transport
stream's offsets are hole-inclusive, so a missing segment already occupies a
range no record covers.

## Session End

| Reason | When |
|--------|------|
| `fin` | Both directions closed cleanly |
| `rst` | Either direction reset |
| `timeout` | Silence longer than `session_timeout` |
| `capture-end` | The capture ran out first |
| `capture-gap` | The specification's value for *the unmeasurable hole* (spec `0.21`): the capture skipped 2³¹ bytes or more of one direction, further than a session can span; the next session, on the same key with no `isn`, continues the connection |

## Blocks zpfwire never writes

| Block | Why |
|-------|-----|
| `Discontinuity` | Decoded-layer only. A transport stream expresses its gaps in its offsets — absolute `seq_start` values make a hole visible by arithmetic — and carrying both would be two accounts of the same missing bytes. |

(zpf-sourced)=

## From a `.zpf` of packets

{func}`~zpfwire.packets.packets_to_zpf` writes the same sessions,
participants and records, through python-zipline's sessionization stage.
Every field above keeps its meaning; these change, because the input is a
`.zpf` rather than a capture.

| Block, field | Value |
|--------------|-------|
| File Header `tick_hz`, `time_epoch` | The input's |
| File Header `comment` | Which labels were selected as packets |
| Source `kind` | `zpf-input`, with the input's `uri` and `sha256` `digest` |
| Record `spans` | **Present**: every input packet the record was built from, whole, in the input's namespace — adjacent packets merged into one range.  A record carrying `seq_start` may cite several, across the input's seams (spec `0.22`) |
| Undecoded `session_id`, `participant_id` | The input stream's, in its own namespace |
| Undecoded `off_start`, `off_end` | The whole packet's range in the input stream's offset space — a packet is marked only when no record cites any of it |
| Undecoded `reason` | As on a capture for what reassembly discarded; `undecodable` for a selected record that is not a packet; `skipped`, written by the stage, for whatever nothing cited or marked |
| Session End `input_extents` | The **whole** extent of every input stream the session cited, the same in every session that cited it |

What the file says about every input byte, and why a packet is cited whole,
is worked through in {doc}`../guide/converting-packets`.

## Two rules that shaped the reassembler

These are the specification requirements that dictate the design rather than
just the output, and they are why {class}`~zpfwire.options.ReassemblyOptions`
exists at all:

1. **Per-participant `seq_start` ordering is a must**, enforced with serial
   arithmetic — 32-bit wrap is legal.
2. **Committing a gap is irreversible.** Having emitted a record past missing
   bytes, those bytes must not be emitted if they turn up later.

Together they require an explicit reorder buffer with a bounded flush policy,
and make that policy a user-visible knob rather than an implementation detail:
it decides what data is thrown away.

## Validation is not reimplemented

The `zpf` writer runs its conformance checker *before* bytes reach the sink,
so a violation raises `zpf.SemanticError` at the offending call rather than
producing a bad file.  zpfwire does not duplicate those checks; it relies on
them, and the test suite asserts that every file it writes reads back with no
diagnostics and nothing unplaceable.
