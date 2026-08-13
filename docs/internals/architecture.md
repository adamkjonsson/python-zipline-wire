# Architecture

One pass over the capture, one session per conversation, one record per run of
contiguous bytes.  Nothing is buffered beyond what reassembly requires, unless
sequencing is asked for.

## The path a packet takes

```
capture file
   │  CaptureReader           packeteer parses; fragments already reassembled
   ▼
PacketView                    one TCP segment or UDP datagram, reduced
   │  packet_filter           optional predicate; rejects counted as `filtered`
   ▼
FlowKey.of(pkt)               direction-free conversation identity
   │
   ▼
FlowTracker                   TcpFlow or UdpFlow, created on first packet
   │  .packet(pkt)
   ▼
SessionWriter.record(...)     zpf validates before bytes reach the sink
   ▼
.zpf
```

`convert.py` owns that loop.  It is deliberately short: everything
interesting is either in the reader below it or the tracker beside it.

## Why the layers are where they are

**`capture.py` knows about link layers; nothing above it does.**  A
`PacketView` has an address, a port, a payload, and TCP's sequence fields.  It
does not have an Ethernet header, an IP version, or a fragment offset.  That
boundary is what let the module be rewritten from a hand-rolled layer walk to
a single packeteer call without touching anything else — see
{doc}`capture-seam`.

**`flow.py` knows about the writer; the transports do not.**  Participant
declaration, session end reasons, and the `Undecoded` helper live on
`FlowTracker` because both transports need them identically.  `TcpFlow` and
`UdpFlow` differ only in what a record *is*.

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

A tracker lives until one of four things happens:

| Event | Reason written |
|-------|----------------|
| Both directions closed | `fin` |
| Either direction reset | `rst` |
| Silence past `session_timeout` | `timeout` |
| The capture ran out | `capture-end` |

A timed-out flow is closed and removed from the table, so a later packet
between the same endpoints creates a *new* tracker and a new session.  That is
what stops a long capture producing one enormous session per endpoint pair.

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
