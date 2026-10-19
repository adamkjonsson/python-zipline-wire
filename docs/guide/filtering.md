# Filtering

A conversion takes an optional predicate, called once per packet, that decides
whether the packet is converted:

```python
stats = zpfwire.capture_to_zpf(
    "capture.pcap", "https.zpf",
    packet_filter=lambda pkt: pkt.dst_port == 443,
)
print(stats.filtered)     # packets the predicate rejected
```

The same predicate, and every CLI filter, applies unchanged to the inner
packets of a `.zpf` input ({func}`~zpfwire.packets.packets_to_zpf`).
Filtered packets are counted in
{attr}`~zpfwire.stats.ConversionStats.filtered`, separately from
{attr}`~zpfwire.stats.ConversionStats.skipped`.  The distinction is
deliberate: skipped means *could not be converted*, filtered means *you asked
me not to*.

## Reusing packeteer's filter

Address and port matching has more edge cases than it looks — CIDR ranges,
IPv6, negation — so zpfwire does not implement a second dialect of it.
packeteer's `PacketFilter` already does the job with validated semantics, and
{func}`~zpfwire.filter.matcher` adapts it:

```python
from packeteer.filter import PacketFilter
from zpfwire import matcher

keep = matcher(PacketFilter(
    proto="tcp",
    dst_port=["443"],
    src=["10.0.0.0/24"],
))

stats = zpfwire.capture_to_zpf("capture.pcap", "out.zpf", packet_filter=keep)
```

This is what the CLI flags do; `--dst-port 443 --src 10.0.0.0/24` builds
exactly the filter above.

### What the fields accept

| Field | Matches |
|-------|---------|
| `proto` | The transport: `"tcp"` or `"udp"` |
| `port` | Either port |
| `src_port`, `dst_port` | The source or destination port |
| `src`, `dst` | The source or destination address |
| `host` | Either address |

Every field except `proto` takes a **list** of strings.  Addresses accept
plain addresses and CIDR ranges, in both IPv4 and IPv6.  A value prefixed with
`!` negates:

```python
PacketFilter(host=["!10.0.0.0/8"])       # anything not from the private range
PacketFilter(port=["80", "443", "8080"]) # any of these ports, either end
```

Fields combine with **and**; values within one field combine with **or**.

### `matcher` returns `None` for an empty filter

```python
matcher(PacketFilter())        # → None
matcher(None)                  # → None
```

That is not an error case, it is the useful one: `packet_filter=None` means no
filtering, so an empty filter costs nothing at all rather than a per-packet
call that always returns `True`.  Passing the result straight through is
therefore correct:

```python
stats = zpfwire.capture_to_zpf(
    "capture.pcap", "out.zpf",
    packet_filter=matcher(build_filter_from_user_input()),
)
```

## How the adaptation works

`PacketFilter.matches` expects a packeteer **packet spec** dict, not a
{class}`~zpfwire.capture.PacketView`.  It reads only five keys from it, so
{func}`~zpfwire.filter.spec_of` projects a view into exactly those:

```python
from zpfwire import spec_of

spec_of(pkt)
# {'network':   {'protocol': 'tcp', 'src': '10.0.0.1', 'dst': '10.0.0.2'},
#  'transport': {'src_port': 51000, 'dst_port': 80}}
```

`spec_of` is public because the projection is occasionally useful on its own,
and because knowing what a filter can see is part of knowing what it can do:
a filter cannot match on payload, flags, or sequence numbers, since none of
those appear here.

## Filtering by hand

The predicate is an ordinary callable, so anything a `PacketView` exposes can
drive it:

```python
def keep(pkt):
    return pkt.protocol == "tcp" and pkt.payload and pkt.tcp_flags & 0x08

stats = zpfwire.capture_to_zpf("capture.pcap", "pushed.zpf", packet_filter=keep)
```

Two cautions when filtering below the flow level.

**Filtering breaks streams.** The reassembler sees only what survives the
predicate, so dropping segments from the middle of a connection produces gaps
exactly as packet loss would, and the discarded bytes are counted as lost.
Filtering by address or port keeps whole conversations and is safe; filtering
by payload or flags generally is not.

**The handshake decides `isn`.** A filter that excludes the SYN leaves the
session without an initial sequence number and without participant roles,
because the specification requires `isn` exactly when the handshake was
observed.  The output is still correct — it just says less.

## Filtering versus converting less

Three flags do similar-looking things:

| Approach | Effect | Counted as |
|----------|--------|------------|
| `packet_filter=` | Drops individual packets before flow grouping | `filtered` |
| `tcp=False` / `udp=False` | Drops a whole transport | `skipped["tcp-not-requested"]` |
| Filtering the capture beforehand | Never seen at all | nothing |

Prefer `tcp=`/`udp=` when you want a whole transport gone: it is clearer, and
the summary says so in a way that survives into anyone reading the stats
later.
