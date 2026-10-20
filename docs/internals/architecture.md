# Architecture

One pass over the capture, one session per conversation, one record per run of
contiguous bytes.  Nothing is buffered beyond what reassembly requires, unless
sequencing is asked for.

## The path a packet takes

```
capture file                  or a .zpf of packets
   │  CaptureReader           PacketRecordReader: selects, merges by time,
   │                          defragments and parses the input's records
   ▼
PacketView                    one TCP segment or UDP datagram, reduced
   │  tcp / udp wanted?       a transport switched off is `<proto>-not-requested`
   │  packet_filter           optional predicate; rejects counted as `filtered`
   │  checksum policy         a bad checksum is counted; under "drop" a TCP one ends here, cited
   ▼
FlowKey.of(pkt)               direction-free conversation identity
   │
   ▼
FlowTracker                   TcpFlow or UdpFlow, created on first packet
   │  .packet(pkt)
   ▼
RecordSink.record(...)        CaptureSink: the output file's session
   │                          PacketSink: a sessionization stage's, citing input
   ▼
.zpf                          zpf validates before bytes reach the sink
```

`convert.py` owns that loop, `_drive`, and both inputs share it.  It is
deliberately short: everything interesting is either in the reader below it,
the tracker beside it, or the sink the tracker writes through.

## Why the layers are where they are

**`capture.py` knows about link layers; nothing above it does.**  A
`PacketView` has an address, a port, a payload, and TCP's sequence fields.  It
does not have an Ethernet header, an IP version, or a fragment offset.  That
boundary is what let the module be rewritten from a hand-rolled layer walk to
a single packeteer call without touching anything else — see
{doc}`capture-seam`.

**`flow.py` knows where a session is written; the transports do not.**
Participant declaration, session end reasons, and the `Undecoded` helper live
on `FlowTracker` because both transports need them identically, and they go
through a `RecordSink` — the capture's output file, or a sessionization
stage over a `.zpf` of packets — so neither transport knows which input it
is converting.  `TcpFlow` and `UdpFlow` differ only in what a record *is*.

**`tcp.py` knows about the specification's ordering rules.**  This is where
the design stops being free — see {doc}`tcp-reassembler`.

## Flow identity

A zipline session holds *both* directions of a connection, so the key must be
direction-free.  `FlowKey.of` sorts the two endpoints:

```python
first  = (pkt.src, pkt.src_port)
second = (pkt.dst, pkt.dst_port)
low, high = (first, second) if first <= second else (second, first)
```

so `A → B` and `B → A` produce the same key and reach the same tracker.
packeteer has a similar-looking `_session_key`, but it is deliberately
directional — it only counts half-flows — so it is not shared.

## Lazy participant declaration

Participants are declared on the first packet from that direction, not up
front.  This is what keeps the conversion single-pass.

A TCP participant's `isn` must be present exactly when the handshake was
observed and absent otherwise.  Declaring both participants when the session
opens would mean guessing; declaring each on its own first packet means the
SYN, if there is one, has already been seen.  A direction's first packet
always precedes any record from it, so nothing is ever declared too late.

The far endpoint is declared at `finish()` even if it never spoke, because the
conversation had two ends whether or not both did.

## Session lifetime

A tracker lives until one of five things happens:

| Event | Reason written |
|-------|----------------|
| Both directions closed | `fin` |
| Either direction reset | `rst` |
| Silence past `session_timeout` | `timeout` |
| The capture ran out | `capture-end` |
| A segment from the far side of a hole 2³¹ bytes or wider (`splits_before`) | `capture-gap` |

A timed-out flow is closed and removed from the table, so a later packet
between the same endpoints creates a *new* tracker and a new session.  That is
what stops a long capture producing one enormous session per endpoint pair.
A `capture-gap` split works the same way — the segment that could not join
opens the next tracker — and is the specification's own exit for the shape;
see {doc}`tcp-reassembler`.

## Where the counters live

`ConversionStats` is created by `convert` and passed into every tracker, which
mutates it directly.  That is unusual enough to note: the alternative — each
tracker returning its own tally to be merged — would mean a session's
contribution to `overlap_bytes` is only visible after it closes, and the
figures exist precisely so that nothing is lost quietly.

The reader keeps its own tallies (`packet_count`, `skipped`) because it counts
things no tracker ever sees.  `convert` copies both across at the end:

```python
stats.packets = reader.packet_count
stats.skipped.update(reader.skipped)
```

Both are read from the reader rather than accumulated in the loop, which only
ever sees the packets that survived it.

## The CLI is a wrapper

`__main__.py` is argparse and printing.  Every subcommand handler builds
arguments and calls one library function; no decision that affects output is
made there.  The rule is that anything the CLI can do must be reachable from
Python, so a flag that has no API equivalent is a bug in the API rather than a
feature of the CLI.

What it decides on its own are refusals, each resting on a fact the API
exposes.  `convert` will not run with both transports switched off, or on a
capture whose link type packeteer cannot decode
(`CaptureReader.link_type_supported`): either would be a valid, empty file,
which the library will still write if asked, and the CLI declines to,
because nothing to convert is not a conversion.  And a flag that does not fit
the input's kind (`input_kind`) is refused rather than ignored — `--tick-hz`
with a `.zpf`, which states its own; `--content-type` with a capture — as are
`info` given a `.zpf` and `pcap` given a capture.
