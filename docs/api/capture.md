# Reading a capture

The seam against packeteer.  Everything that knows about link layers, IP
headers, or pcap framing lives here; the rest of zpfwire sees only
{class}`~zpfwire.capture.PacketView` objects.

Fragmented datagrams are reassembled before parsing, so a fragment is never
mistaken for a whole packet, and a datagram whose fragments never all arrived
is counted rather than dropped silently.

---

## The reader

```{eval-rst}
.. autoclass:: zpfwire.capture.CaptureReader
   :members:
```

---

## What it yields

```{eval-rst}
.. autoclass:: zpfwire.capture.PacketView
   :members:
```

---

## What it could not convert

```{eval-rst}
.. autoclass:: zpfwire.capture.SkipReason
   :members:
```

---

## Helpers

```{eval-rst}
.. autofunction:: zpfwire.capture.format_endpoint
```

```{eval-rst}
.. autodata:: zpfwire.capture.TICK_HZ_US
```

```{eval-rst}
.. autodata:: zpfwire.capture.TICK_HZ_NS
```
