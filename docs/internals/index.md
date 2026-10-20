# Developer internals

This section describes how zpfwire works internally.  It is aimed at
contributors and at users who want to extend the conversion beyond what the
public API exposes.

## Structure of this section

```{toctree}
:maxdepth: 1

architecture
capture-seam
tcp-reassembler
writer-mapping
upstream-first
testing
contributing
```

## Module map

Roughly 4,500 lines of source, and the ordering below is the order data moves
through them.

| Module | Purpose |
|--------|---------|
| `zpfwire/capture.py` | The packeteer seam — capture file to `PacketView` stream, and the skip tally |
| `zpfwire/packets.py` | A `.zpf` of packets as input: the reader, the sink that cites input packets, `packets_to_zpf` and `packets_to_pcap` |
| `zpfwire/flow.py` | `FlowKey` (direction-free conversation identity), `FlowTracker` (what every transport shares), and `RecordSink` (where a session is written) |
| `zpfwire/tcp.py` | `TcpFlow` — the reassembler: reorder buffer, gap policy, run coalescing |
| `zpfwire/udp.py` | `UdpFlow` — one datagram, one record |
| `zpfwire/convert.py` | Orchestration: open, hash, declare, drive the flows, close — the loop shared by both inputs |
| `zpfwire/options.py` | `ReassemblyOptions` and the `params_digest` that makes a conversion reproducible |
| `zpfwire/stats.py` | `ConversionStats` — the accounting that stops loss being silent |
| `zpfwire/survey.py` | `survey` — what a conversion *would* produce |
| `zpfwire/filter.py` | Adapter onto packeteer's `PacketFilter` |
| `zpfwire/__main__.py` | CLI — argparse only, all logic in the library |

## The shape of the whole thing

zpfwire owns no file format and no packet parser.  Both of its dependencies do
one job each, and neither knows about the other:

```
capture ──packeteer──→ ParsedPacket ──zpfwire──→ sessions/records ──zpf──→ .zpf
.zpf of packets ──zpf──→ records ──packeteer──→ ParsedPacket ──zpfwire──→ …
```

Everything here is the middle arrow.  Two consequences run through the whole
codebase and are worth holding in mind before changing anything:

**Gaps found in a dependency get fixed there, not worked around here.**  That
is the project's reason for existing as much as the converter is — see
{doc}`upstream-first`.

**The output shape is dictated by the specification**, not by taste.  Several
things that look like design choices are requirements, and
{doc}`writer-mapping` names which.
