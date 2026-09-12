# The capture seam

`capture.py` is the only module that knows about link layers, IP headers, or
pcap framing.  Everything above it sees `PacketView` objects.

Today it is a thin wrapper over one packeteer call.  It was not always, and
the history is the clearest illustration of how this project is meant to work.

## What it does now

```python
with iter_packets(path=path, decode_app=False) as reader:
    tick_hz, link_type = reader.header.tick_hz, reader.header.link_type
    for packet in reader:
        ...
    dropped = reader.incomplete
```

`iter_packets` opens the file, reassembles IP fragments, and parses each
result, streaming one packet at a time.  `reader.header` is populated before
the first packet, which suits the writer: the `.zpf` File Header and Source
Descriptor can be written before any record is read.

What is left for this module is the mapping onto our model — deciding what
counts as convertible, tallying what does not, and putting every timestamp on
one clock.

## What it used to be, and why

The obvious call was always `parse_packet`.  It was unusable, and four other
things had to be done by hand, so the module was a ~120-line layer walk
driving packeteer's per-layer parsers directly and slicing by the header sizes
they reported.

Every one of those five reasons was filed upstream and fixed there:

| Problem | Workaround here | Fixed by |
|---------|-----------------|----------|
| The parser ran DNS/DHCP/HTTP decoders unconditionally and replaced the payload, so `payload` was empty on exactly the ports a payload format exists to serve | Bypass `parse_packet` entirely | `decode_app=False` (packeteer#61) |
| Ethernet padding on short frames was reported as transport payload | Read the IP length from raw bytes and trim | The parser trims it (packeteer#66) |
| No IP defragmentation, and a *first* fragment parses a transport header over a truncated payload | Skip and count every fragment | `Defragmenter`, on by default (packeteer#65) |
| `payload_offset` unavailable, and `len(frame) - len(payload)` is wrong once padding is trimmed | No byte-level provenance at all | `ParsedPacket.payload_offset` (packeteer#71) |
| A bare generator exposed neither the capture header nor what reassembly dropped | Compose three calls by hand | `PacketReader` (packeteer#76) |

The rewrite deleted the walk, the raw-bytes length read, a `tick_hz_for`
helper and a `_frac_scale` field, and dropped the fragment check — while
gaining link-type support for SLL/SLL2, ARP, MPLS, PPPoE and the tunnel stack,
which the hand-walk had never handled.

The lesson worth keeping: **the boundary held.**  `PacketView` did not change
shape, so nothing above `capture.py` was touched.

A sixth shim came and went the same way, after packeteer 0.9.0 made a
surviving `checksum` mean *wrong on the wire*: the parser kept the field on a
snaplen-truncated packet too, where the value it derived came from fewer bytes
than the sender used, so a truncated capture read as corruption throughout.
`_checksum_bad` carried a `_truncated` guard for one release; packeteer 0.9.1
clears the field itself (packeteer#92) and the guard is gone.

## Skip reasons

`ParsedPacket` says what each layer contained, not *why* one is missing, so
the reasons are reconstructed — with one exception, decided before any packet
is read.

**The link type is a property of the file, and it is asked, not inferred.**
`CaptureReader.__init__` calls `packeteer.parse.supports_link_type` on the
header's link type (an override lands there too) and keeps the answer as
`link_type_supported`.  When it is `False`, `__iter__` tallies every record as
`UNSUPPORTED_LINKTYPE` without looking at it, and silences the
`UnsupportedLinkTypeWarning` packeteer would otherwise raise for saying the
same thing.

That used to be inferred per packet, from every link-layer object being
`None` — and that is also what a raw-IP packet with a bad IP header looks
like, because `LINKTYPE_RAW` has no link-layer header to parse.  The packet
cannot tell the two apart (`offsets == {}` in both), which is why the fact has
to come from the file (packeteer#138).  The ladder now takes it as an
argument:

```python
if packet.ip is None:
    if headerless:                          # raw IP: the link type announced IP
        return SkipReason.MALFORMED_IP
    if packet.loopback is not None:
        return _loopback_skip_reason(packet.loopback)
    if ethertype in (ETHERTYPE_IPV4, ETHERTYPE_IPV6):
        return SkipReason.MALFORMED_IP      # announced IP, none parsed
    return SkipReason.NON_IP
```

The distinction worth preserving is the last one.  An IP header names its
transport, so a datagram declaring protocol 6 with no TCP header is a *parse
failure*, while protocol 132 is a protocol we decline:

```python
if _ip_protocol(packet) in (IPPROTO_TCP, IPPROTO_UDP):
    return SkipReason.MALFORMED_TRANSPORT
return SkipReason.NOT_TCP_UDP
```

Without consulting the IP header both cases look identical — `transport is
None` — and a report that conflated them would call a truncated capture a
protocol choice.

`INCOMPLETE_DATAGRAM` is the odd one out: it counts *datagrams*, not packets,
and comes from `reader.incomplete` after iteration rather than from any single
packet.  It is therefore the one skip reason not included in `packet_count`.

## Timestamps

Every `PacketView.ts_ticks` is on the reader's clock:

```python
source_hz = packet.tick_hz or self.tick_hz
if source_hz == self.tick_hz:
    return packet.ts_sec * self.tick_hz + packet.ts_frac
return packet.ts_sec * self.tick_hz + (packet.ts_frac * self.tick_hz) // source_hz
```

Two things here are deliberate.

**Rescaling is per packet, not per file.**  A pcapng states its resolution per
*interface*, so two packets in one capture need not be counted in the same
unit, while a `.zpf` File Header carries exactly one tick rate.  Assuming they
match would silently misplace packets from the other interfaces.

**The arithmetic multiplies before dividing.**  The obvious
`ts_frac * (tick_hz // source_hz)` floors to zero whenever the target rate is
*coarser* than the source — a `--tick-hz 1000` override against a microsecond
capture would collapse every sub-second time to the whole second.

## Re-iteration

The reader opens the file once at construction to read the header, and again
for each iteration.  Iterating twice re-reads and resets the tallies, which is
what lets a caller survey a reader and then convert it.

For a `file_object` the reader seeks to zero before each pass; packeteer never
closes a caller's file object, so this is safe.  A reader opened from a path
closes what it opened.

## What is still hand-rolled

Nothing, and that is the point.  The one remaining local decision — how to
classify a skip — exists because `ParsedPacket` reports absence rather than
cause, which is a reasonable thing for a parser to do.
