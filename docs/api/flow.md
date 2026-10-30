# The flow layer

Grouping packets into the conversations that become sessions, and turning each
conversation's packets into that session's records.

Most callers never touch this: {func}`~zpfwire.convert.capture_to_zpf` wires it
up.  It is public so that the conversion can be extended — a new transport is
a new {class}`~zpfwire.flow.FlowTracker` subclass and one entry in
`convert._TRACKERS`.

---

## Identifying a conversation

A zipline session holds *both* directions of a connection, so the key has to
be direction-free: the two endpoints are sorted, and a packet from either side
yields the same key.

```{eval-rst}
.. autoclass:: zpfwire.flow.FlowKey
   :members:
```

---

## The tracker

Subclasses differ only in what a record *is* for their transport — a UDP
datagram, or a run of reassembled TCP bytes — so the writer wiring,
participant bookkeeping, and end-reason handling live on the base.

Participants are declared lazily, on the first packet from that direction.
That is what lets the conversion stay single-pass: a direction's first packet
always precedes any record from it, so per-participant metadata that must be
fixed at declaration time — notably a TCP stream's `isn` — is known by then
whenever it is knowable at all.

```{eval-rst}
.. autoclass:: zpfwire.flow.FlowTracker
   :members:
```

---

## Where a session is written

A tracker writes through a sink, so the same tracker converts a capture and a
`.zpf` of packets.  {class}`~zpfwire.flow.CaptureSink` is the capture's;
{class}`~zpfwire.packets.PacketSink` is the `.zpf`'s.

```{eval-rst}
.. autoclass:: zpfwire.flow.RecordSink
   :members:
```

```{eval-rst}
.. autoclass:: zpfwire.flow.CaptureSink
   :members:
```

Both write an Undecoded block against the capture through one function, which
a caller building its own sink can use too:

```{eval-rst}
.. autofunction:: zpfwire.flow.cite_undecoded
```

---

## Per-transport trackers

```{eval-rst}
.. autoclass:: zpfwire.tcp.TcpFlow
   :members:
```

```{eval-rst}
.. autoclass:: zpfwire.udp.UdpFlow
   :members:
```

---

## Session End reasons

Every session carries one.  See {doc}`../guide/converting`.

```{eval-rst}
.. autodata:: zpfwire.tcp.END_FIN
```

```{eval-rst}
.. autodata:: zpfwire.tcp.END_RST
```

```{eval-rst}
.. autodata:: zpfwire.flow.END_TIMEOUT
```

```{eval-rst}
.. autodata:: zpfwire.flow.END_CAPTURE_END
```

```{eval-rst}
.. autodata:: zpfwire.tcp.END_CAPTURE_GAP
```

---

## Undecoded reasons

The `reason` strings on the `Undecoded` blocks a conversion writes.  All are
of the *bytes-exist* class: the bytes are in the capture, and a consumer may
follow the reference to fetch them.  See {doc}`../guide/provenance`.

```{eval-rst}
.. autodata:: zpfwire.flow.REASON_OVERLAP
```

```{eval-rst}
.. autodata:: zpfwire.flow.REASON_DUPLICATE
```

```{eval-rst}
.. autodata:: zpfwire.flow.REASON_LATE
```

```{eval-rst}
.. autodata:: zpfwire.flow.REASON_LATE_REORDERED
```

```{eval-rst}
.. autodata:: zpfwire.flow.REASON_LATE_RETRANSMITTED
```

```{eval-rst}
.. autodata:: zpfwire.flow.REASON_PAWS
```

```{eval-rst}
.. autodata:: zpfwire.flow.REASON_TS_MISSING
```

```{eval-rst}
.. autodata:: zpfwire.flow.REASON_CHECKSUM
```

```{eval-rst}
.. autodata:: zpfwire.flow.REASON_UNDECODABLE
```

When a repeat could not be judged by the Timestamps option it is cited as
`REASON_OVERLAP` — the conservative reading — and the reason it could not be
is counted under one of these keys in
{attr}`~zpfwire.stats.ConversionStats.ts_fallback`:

```{eval-rst}
.. autodata:: zpfwire.tcp.TS_ABSENT
```

```{eval-rst}
.. autodata:: zpfwire.tcp.TS_STALE
```
