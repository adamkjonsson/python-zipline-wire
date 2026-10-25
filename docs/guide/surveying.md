# Looking before converting

{func}`~zpfwire.survey.survey` reports the conversations a capture holds
without writing anything.  It reads captures only; for a `.zpf` of packets,
convert it and read the summary.  It is the same flow grouping a conversion uses, so
it answers "what would I get?" ahead of committing to an output file.

```python
from zpfwire import CaptureReader, survey

reader = CaptureReader(path="capture.pcap")
for flow in survey(reader):
    print(flow.key.text, flow.packets, flow.payload_bytes)
```

```
10.0.0.1:51000 <-> 10.0.0.2:80 207 78388
```

## What a summary holds

Each {class}`~zpfwire.survey.FlowSummary` describes one conversation:

| Attribute | Meaning |
|-----------|---------|
| `key` | The {class}`~zpfwire.flow.FlowKey`, which becomes the session's `key` |
| `packets` | Packets seen, both directions |
| `payload_bytes` | Transport payload **before** reassembly |
| `first_ts`, `last_ts` | First and last packet times, in ticks |
| `endpoints` | Which endpoints actually sent something |

`payload_bytes` counts what was on the wire, so on a capture with retransmits
it exceeds what a conversion writes.  The difference is the overlap that
reassembly discards — which is the point of looking first.

Ticks are not seconds.  Divide by the reader's rate, or use the helper:

```python
flow.duration(reader.tick_hz)     # seconds
```

`endpoints` is worth checking on a capture you do not trust: a conversation
where only one endpoint appears is one where the other side's traffic was
never captured, and its session will have a participant that says nothing.

## Reading the tallies afterwards

The reader counts what it saw *as it iterates*, so its counters are only
meaningful after `survey` has run:

```python
reader = CaptureReader(path="capture.pcap")
flows = survey(reader)

reader.packet_count      # packets seen — 0 before iteration
reader.skipped           # Counter keyed by SkipReason
reader.tick_hz           # the rate every timestamp is expressed in
reader.link_type         # from the capture header
reader.link_type_supported  # whether packeteer can decode it at all
reader.snaplen           # the capture limit, or None when it states none
```

`header`, `tick_hz`, `link_type`, `link_type_supported` and `snaplen` are
available immediately, because the capture's header is read when the reader
is constructed — and `link_type_supported` is worth checking first, since
when it is `False` the survey will be empty and every packet skipped.  `packet_count` and
`skipped` are not, because knowing them means reading the file.

## Surveying a filtered view

`survey` takes the same predicate a conversion does, so a filter can be tried
before it is trusted:

```python
from zpfwire import matcher, spec_of
from packeteer.filter import PacketFilter

keep = matcher(PacketFilter(dst_port=["443"]))
flows = survey(reader, packet_filter=keep)
```

See {doc}`filtering`.

## Sizing up a capture

The pattern behind `zpfwire info` — biggest conversations first, then what was
skipped:

```python
from zpfwire import CaptureReader, survey

reader = CaptureReader(path="capture.pcap")
flows = sorted(survey(reader), key=lambda f: -f.payload_bytes)

print(f"{reader.packet_count} packets, {len(flows)} conversations")
for flow in flows[:10]:
    print(f"{flow.payload_bytes:>10}  {flow.key.text}")
for reason, count in sorted(reader.skipped.items()):
    print(f"skipped {count} ({reason})")
```

A conversation with zero `payload_bytes` carries no data — a
pure-acknowledgement exchange, or a connection whose data was never
captured.  Its session holds one zero-length record per pure ACK, or, under
`--no-pure-acks`, no records at all.  Those sessions are still written,
because the conversation existed; with no records they are also the case
that makes a TCP session hint-less, which matters for {doc}`ordering`.

## Iterating packets directly

`survey` is a small function over the reader, and the reader is public.  When
you want the packets rather than a summary:

```python
reader = CaptureReader(path="capture.pcap")
for pkt in reader:
    print(pkt.packet_num, pkt.protocol, pkt.src_endpoint, len(pkt.payload))
```

Each is a {class}`~zpfwire.capture.PacketView` — one TCP segment or UDP
datagram reduced to what reassembly needs.  Iterating twice re-reads the file
and resets the tallies, so a reader can be surveyed and then converted.
