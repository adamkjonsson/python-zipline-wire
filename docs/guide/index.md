# Python API Guide

This part covers the zpfwire Python API through a series of focused,
task-oriented chapters.  Each chapter shows how to accomplish a common goal
without exhaustive parameter lists — those live in {doc}`../api/index`.

Everything public is importable from the top-level `zpfwire` package:

| Name | What it is |
|------|------------|
| `capture_to_zpf` | The one-call conversion: capture in, `.zpf` out |
| `convert` | The lower half, for a caller who built their own reader |
| `describe_source` | Hash a capture, for the Source Descriptor |
| `CaptureReader`, `PacketView`, `SkipReason` | Reading a capture as convertible packets |
| `ReassemblyOptions`, `OVERLAP_POLICIES`, `CHECKSUM_POLICIES`, `DECODER_NAME` | The policy that decides which bytes survive |
| `ConversionStats` | What a conversion did, and what it could not do |
| `survey`, `FlowSummary` | Looking at a capture without writing anything |
| `matcher`, `spec_of` | Filtering, on top of packeteer's `PacketFilter` |
| `FlowKey`, `FlowTracker`, `TcpFlow`, `UdpFlow` | The flow layer, for extending the conversion |
| `REASON_OVERLAP`, `REASON_LATE`, `REASON_CHECKSUM` | The `reason` strings on `Undecoded` blocks |
| `END_FIN`, `END_RST`, `END_TIMEOUT`, `END_CAPTURE_END` | The Session End reasons |
| `format_endpoint`, `TICK_HZ_US`, `TICK_HZ_NS`, `tool_version` | Small helpers |

The shortest useful program is one line of work:

```python
import zpfwire

stats = zpfwire.capture_to_zpf("capture.pcap", "capture.zpf")
print(stats.summary())
```

Everything else in this guide is about controlling what that line does, and
about reading what it reports.

```{toctree}
:maxdepth: 1

converting
surveying
filtering
reassembly
provenance
ordering
```
