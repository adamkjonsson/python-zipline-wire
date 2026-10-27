# Python API Guide

This part covers the zpfwire Python API through a series of focused,
task-oriented chapters.  Each chapter shows how to accomplish a common goal
without exhaustive parameter lists — those live in {doc}`../api/index`.

Everything public is importable from the top-level `zpfwire` package,
except `zpfwire.fidelity` (the last row), which is imported by name:

| Name | What it is |
|------|------------|
| `capture_to_zpf` | The one-call conversion: capture in, `.zpf` out |
| `packets_to_zpf`, `input_kind` | The same, from a `.zpf` of packets such as a decrypted tunnel's |
| `packets_to_pcap`, `PcapExport` | Those packets written to a pcap, for Wireshark |
| `convert` | The lower half, for a caller who built their own reader |
| `describe_source` | Hash a capture, for the Source Descriptor |
| `CaptureReader`, `PacketView`, `SkipReason` | Reading a capture as convertible packets |
| `PacketRecordReader`, `SKIP_FRAGMENTED_UDP`, `REASON_UNDECODABLE` | Reading a `.zpf` of packets the same way |
| `ReassemblyOptions`, `OVERLAP_POLICIES`, `CHECKSUM_POLICIES`, `DECODER_NAME` | The policy that decides which bytes survive |
| `ConversionStats` | What a conversion did, and what it could not do |
| `survey`, `FlowSummary` | Looking at a capture without writing anything |
| `matcher`, `spec_of` | Filtering, on top of packeteer's `PacketFilter` |
| `FlowKey`, `FlowTracker`, `TcpFlow`, `UdpFlow` | The flow layer, for extending the conversion |
| `RecordSink`, `CaptureSink`, `PacketSink` | Where a tracker's session is written, for either input |
| `REASON_OVERLAP`, `REASON_LATE`, `REASON_CHECKSUM` | The `reason` strings on `Undecoded` blocks |
| `END_FIN`, `END_RST`, `END_TIMEOUT`, `END_CAPTURE_END` | The Session End reasons |
| `format_endpoint`, `TICK_HZ_US`, `TICK_HZ_NS`, `tool_version` | Small helpers |
| `zpfwire.fidelity`: `evaluate`, `Scenario`, `measure` … | Measuring a policy against traffic packeteer generates; see {doc}`choosing-a-policy` |

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
converting-packets
surveying
filtering
reassembly
provenance
ordering
choosing-a-policy
```
