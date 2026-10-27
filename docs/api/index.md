# API Reference

Everything public is importable from the top-level `zpfwire` package.  The
pages below group it by the stage of a conversion it belongs to.

**Conversion** is {func}`~zpfwire.convert.capture_to_zpf` — capture in, `.zpf`
out — with {func}`~zpfwire.convert.convert` as the lower half for callers who
built their own reader, and {func}`~zpfwire.convert.describe_source` for the
digest a Source Descriptor needs.  {func}`~zpfwire.packets.packets_to_zpf`
is the same conversion from a `.zpf` of packets — a decrypted tunnel's inner
traffic — and {func}`~zpfwire.packets.input_kind` tells the two inputs
apart.  What a conversion did comes back as
{class}`~zpfwire.stats.ConversionStats`.

**Reading a capture** is {class}`~zpfwire.capture.CaptureReader`, which yields
{class}`~zpfwire.capture.PacketView` objects and tallies whatever it could not
convert under a {class}`~zpfwire.capture.SkipReason`.  This is the seam
against packeteer; nothing above it knows about link layers or pcap framing.

**Policy** is {class}`~zpfwire.options.ReassemblyOptions`, whose
{meth}`~zpfwire.options.ReassemblyOptions.params_digest` is recorded on the
file's decoder descriptor.

**The flow layer** — {class}`~zpfwire.flow.FlowKey`,
{class}`~zpfwire.flow.FlowTracker`, {class}`~zpfwire.tcp.TcpFlow`,
{class}`~zpfwire.udp.UdpFlow` — turns grouped packets into a session's
records, written through a {class}`~zpfwire.flow.RecordSink`.  It is public so that a caller can extend the conversion, not because
an ordinary conversion needs it.

**Measuring a conversion** is {doc}`fidelity`: `zpfwire.fidelity`, which
generates TCP traffic under chosen impairments, converts it, and scores the
file against what was sent.  It is the one module not imported by
`import zpfwire`, since it loads packeteer's generators.

**Looking without writing** is {func}`~zpfwire.survey.survey`, returning
{class}`~zpfwire.survey.FlowSummary` objects, and
{func}`~zpfwire.filter.matcher` for the predicate a conversion takes.

```{toctree}
:maxdepth: 1

convert
packets
capture
options
stats
flow
survey
fidelity
```
