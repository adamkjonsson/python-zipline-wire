# Converting a capture

{func}`~zpfwire.convert.capture_to_zpf` is the whole conversion in one call:

```python
import zpfwire

stats = zpfwire.capture_to_zpf("capture.pcap", "capture.zpf")
print(stats.summary())
```

It opens the capture, hashes it, creates the writer, declares the source and
the decoder, drives every conversation, and closes the file.  What comes back
is a {class}`~zpfwire.stats.ConversionStats` describing what happened.  A
`.zpf` of packets — a decrypted tunnel's — converts the same way through
{func}`~zpfwire.packets.packets_to_zpf`; see {doc}`converting-packets`.

## Sources and sinks

Both ends accept a path or an open binary stream, so a conversion can run
entirely in memory:

```python
import io

with open("capture.pcap", "rb") as capture:
    out = io.BytesIO()
    stats = zpfwire.capture_to_zpf(capture, out)
```

A stream source is read from position zero and left where it was found.  It is
hashed as well, but has no URI to record — the resulting Source Descriptor
carries a digest and no `uri`, which is honest for input that has no name.

## Choosing the output face

The format has two faces holding the same content: the binary container, and a
JSON-Lines projection that is diffable and greppable.

```python
zpfwire.capture_to_zpf("capture.pcap", "capture.jsonl", face="jsonl")
```

Use `jsonl` when you want to read the output, `binary` (the default) when you
want to store or transmit it.

## Selecting traffic

```python
stats = zpfwire.capture_to_zpf(
    "capture.pcap", "tcp-only.zpf",
    tcp=True,
    udp=False,
)
```

Disabling both raises `ValueError` — it would leave nothing to convert.
Packets excluded this way are counted under `udp-not-requested` in
{attr}`~zpfwire.stats.ConversionStats.skipped`, so the accounting still closes.

For address- and port-level selection, see {doc}`filtering`.

## Overriding what the capture says

```python
stats = zpfwire.capture_to_zpf(
    "headerless.pcap", "out.zpf",
    link_type=1,          # Ethernet, for input whose header does not say
    tick_hz=1_000_000,    # the file's declared resolution is wrong
)
```

Both are escape hatches.  The link type is read from the file header, and the
tick rate from the header and each packet's own interface, so neither is
normally needed — see {doc}`../internals/capture-seam` for what the reader
does with them.

## Reading the result

{class}`~zpfwire.stats.ConversionStats` is a plain dataclass, so every figure
in the printed summary is available as a field:

```python
stats = zpfwire.capture_to_zpf("capture.pcap", "capture.zpf")

stats.packets            # every packet the reader saw
stats.converted          # packets that reached a conversation
stats.sessions           # conversations written
stats.records            # records written
stats.payload_bytes      # bytes that reached the output

stats.skipped            # Counter, keyed by SkipReason
stats.filtered           # excluded by a filter

stats.gaps               # records written past bytes that never arrived
stats.late_bytes         # bytes that arrived after their gap closed
stats.overlap_bytes      # retransmits discarded as already-accepted
stats.undecoded_regions  # capture ranges cited as reaching no record
stats.unlocatable_bytes  # discarded bytes whose capture range cannot be named

stats.bad_checksum           # packets whose checksum did not verify, either policy
stats.checksum_dropped_bytes # TCP payload discarded with them, under checksum="drop"
stats.truncated              # packets the capture's snaplen cut short

stats.records_read           # a .zpf input's records, and those selected as packets;
stats.records_selected       # both 0 for a capture
```

The convenience predicate for "did anything get lost":

```python
if not stats.lossless:
    print(f"{stats.gaps} gaps, {stats.late_bytes} bytes dropped")
```

`lossless` is about *stream* bytes — gaps and late arrivals.  Discarded
overlap does not make a conversion lossy, because those bytes did reach the
output the first time they were seen.

## Checking the file reads back

A conversion that produces a file the reader rejects has not converted
anything.  This is the assertion the project's own test suite makes about
every file it writes, and it is worth making in yours:

```python
import zpf

with zpf.open("capture.zpf") as reader:
    for session in reader.sessions():
        for record in session.records():
            ...
    assert reader.diagnostics == []
    assert reader.unplaceable == []
```

Diagnostics accumulate as the file is read, so they are only complete once the
sessions and their records have been walked.  `unplaceable` is a second list
because since spec `0.19` a record the offset space cannot place breaks no
rule — the file reads clean — and that list is the only thing that says a
producer discarded its own bytes.

## The two-step form

{func}`~zpfwire.convert.convert` is the lower half, for a caller who has
already built a {class}`~zpfwire.capture.CaptureReader` — to survey it first,
to iterate it themselves, or to override how it was opened:

```python
from zpfwire import CaptureReader, convert, describe_source, survey

reader = CaptureReader(path="capture.pcap")
flows = survey(reader)
if len(flows) > 100:
    raise SystemExit(f"{len(flows)} conversations; filter first")

digest, uri = describe_source("capture.pcap")
stats = convert(reader, "capture.zpf", digest=digest, uri=uri)
```

Pass `digest` and `uri` explicitly here.  `capture_to_zpf` computes them for
you; `convert` writes what it is given, and a Source Descriptor without a
digest cannot be checked against the capture it came from later.

{func}`~zpfwire.convert.describe_source` returns `(digest, uri)`, either of
which may be `None` when the source is an unnamed stream.

## What ends a session

Every session carries a reason:

| Constant | Value | When |
|----------|-------|------|
| `END_FIN` | `"fin"` | Both directions closed cleanly |
| `END_RST` | `"rst"` | Either direction reset the connection |
| `END_TIMEOUT` | `"timeout"` | Silence longer than `session_timeout` |
| `END_CAPTURE_END` | `"capture-end"` | The capture ran out first |
| `END_CAPTURE_GAP` | `"capture-gap"` | The capture skipped 2³¹ bytes or more of one direction — further than a session can span.  The specification's own value for the shape, since `0.21` |

A timed-out conversation is closed and a later packet between the same
endpoints starts a *new* session, so one flow can produce several.  So does a
`capture-gap`: a segment from the far side of a hole that wide cannot be
placed in the session it belongs to — records are stored in serial order,
and one that far past its predecessor *precedes* it — so the session ends
there and the segment opens the next.  Only the TCP Timestamps option can
recognise the shape; see {doc}`reassembly`.  UDP has no close, so a UDP
session ends with `timeout` or `capture-end`.
