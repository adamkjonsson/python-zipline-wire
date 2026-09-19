# Specification mapping

What each of zpfwire's objects becomes in the written file, field by field.
Everything here follows from one fact: the output is **capture-sourced** and
**transport-layer**.  Where a field is absent, the rule that forbids it is
named — an absent field in this format is usually a statement, not an
omission.

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

The `isn` rule is a **must** in both directions: present when known, absent
when not.  This is why participant declaration is lazy rather than done up
front — the SYN has to have been seen first.

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
| `flags` | `PSH` / `FIN` / `RST` / `URG` as seen; `RETRANSMIT` when a repeated segment was discarded while the record was accumulating — see below; `MESSAGE` for a UDP datagram |
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
set it.  This reassembler does not read the TCP Timestamps option, so it
cannot tell the two apart, and it takes the specification's fallback for a
producer in that position: every discarded repeat is treated as a
retransmission, and sets the flag on whichever record was accumulating when
it was discarded.  What was discarded is cited either way, as an `Undecoded`
block naming the bytes in the capture — see {doc}`../guide/provenance`.
Telling a duplicate from a resend is
[#17](https://github.com/adamkjonsson/python-zipline-wire/issues/17).

### Fields deliberately absent

| Field | Why |
|-------|-----|
| `content_type` | **Forbidden** at the transport layer — a byte run has no media type. The writer raises on it. |
| `spans` | Every span must reference a `zpf-input` source, and ours is a capture. This is why `ts_first` exists. |

## Undecoded

Written for bytes that are in the capture and reached no record.

| Field | Value |
|-------|-------|
| `source_id` | The capture source |
| `session_id`, `participant_id` | **`0`** — against a capture source there is no input `.zpf`, so there is no id namespace to name |
| `off_start`, `off_end` | Byte offsets **into the capture file**, half-open |
| `reason` | `overlap-discarded`, `late-arrival`, or `bad-checksum` under `checksum="drop"` |
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
| `capture-gap` | The capture skipped further than a session can span; the next session continues the connection |

## Blocks zpfwire never writes

| Block | Why |
|-------|-----|
| `Discontinuity` | Decoded-layer only. A transport stream expresses its gaps in its offsets — absolute `seq_start` values make a hole visible by arithmetic — and carrying both would be two accounts of the same missing bytes. |
| Any `zpf-input` Source | There is no predecessor `.zpf`; the input is a capture. |

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
