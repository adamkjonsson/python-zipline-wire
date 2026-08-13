# `zpfwire info`

Report the conversations a capture holds, without writing anything.

```bash
zpfwire info capture.pcap
```

```
tests/captures/http_example.pcapng: 13 packets, tick_hz 1000000
4 conversation(s) would become sessions

proto   packets    payload  seconds  flow
tcp           4       3138    0.172  146.190.62.39:80 <-> 192.168.1.15:64774
tcp           3          0    0.177  146.190.62.39:80 <-> 192.168.1.15:64778
tcp           3          0    0.177  146.190.62.39:80 <-> 192.168.1.15:64779
tcp           3          0    0.177  146.190.62.39:80 <-> 192.168.1.15:64780
```

This is a preview of what `convert` would do, produced by the same flow
grouping and the same filters, so it is the cheap way to check a filter before
committing to an output file.

## Reading the report

**`13 packets`** is every packet the reader saw, including the ones no
conversation could use.

**`tick_hz 1000000`** is the capture's timestamp resolution in ticks per
second — microseconds here, `1000000000` for a nanosecond pcapng.  It becomes
the tick rate of the file `convert` would write.

**`4 conversation(s)`** counts flows, not packets.  A flow is one conversation
in *both* directions: the two endpoints are sorted into a canonical key, so
`A → B` and `B → A` are the same row and the same future session.

The columns:

| Column | Meaning |
|--------|---------|
| `proto` | `tcp` or `udp` |
| `packets` | Packets seen in the conversation, both directions |
| `payload` | Transport payload bytes **before** reassembly — retransmitted bytes are still counted here |
| `seconds` | Time from the conversation's first packet to its last |
| `flow` | The canonical key, which becomes the session's `key` |

The `payload` column is the one most likely to mislead.  It is what was on the
wire, so on a capture with retransmits it is larger than what a conversion
writes; the difference is the discarded overlap.  Three of the four rows above
show `0` payload, which is worth knowing before converting: those conversations
are pure acknowledgements and will produce sessions with no records at all.

Rows are sorted by payload, largest first, so the conversations worth looking
at come first in a capture with many flows.

## Skipped packets

Anything that could not become part of a conversation is reported by reason
after the table:

```
$ zpfwire info sctp.pcap

proto   packets    payload  seconds  flow

skipped 207 (not-tcp-or-udp)
```

| Reason | Meaning |
|--------|---------|
| `unsupported-linktype` | No link-layer header could be read at all |
| `non-ip` | The link layer carried something else — ARP, for instance |
| `malformed-ip-header` | The link layer announced IP, but no IP header parsed |
| `not-tcp-or-udp` | An IP datagram carrying another transport |
| `malformed-transport-header` | The IP header announced TCP or UDP, but no transport header parsed |
| `incomplete-datagram` | A fragmented datagram whose fragments never all arrived, counted once per datagram |

The last is the only one that is not a whole packet: fragments are reassembled
before parsing, so a datagram missing a piece is dropped as a unit.

## Filtering the preview

The filtering flags apply exactly as they do to `convert`:

```bash
zpfwire info capture.pcap --dst-port 443 --src 10.0.0.0/24
```

Filtered packets are silently absent from the table rather than reported as
skipped — they were excluded on purpose, not lost.

## From Python

`info` is a formatting layer over {func}`~zpfwire.survey.survey`, which returns
the same information as {class}`~zpfwire.survey.FlowSummary` objects:

```python
from zpfwire import CaptureReader, survey

reader = CaptureReader(path="capture.pcap")
for flow in sorted(survey(reader), key=lambda f: -f.payload_bytes):
    print(flow.key.text, flow.packets, flow.payload_bytes)

print(reader.packet_count, dict(reader.skipped))
```

Note the order: `reader.packet_count` and `reader.skipped` are populated by
the iteration that `survey` performs, so they are only meaningful after it.
See {doc}`../guide/surveying`.
