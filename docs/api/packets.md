# A `.zpf` of packets

Converting the inner traffic of a decrypted tunnel — records labelled
`net:ip`, `net:ethernet`, or a decoder's own label — into the sessions inside
it.  See {doc}`../guide/converting-packets` for what the output says and why.

---

## One-call conversion

```{eval-rst}
.. autofunction:: zpfwire.packets.packets_to_zpf
```

```{eval-rst}
.. autofunction:: zpfwire.packets.input_kind
```

---

## Exporting to a pcap

```{eval-rst}
.. autofunction:: zpfwire.packets.packets_to_pcap
```

```{eval-rst}
.. autoclass:: zpfwire.packets.PcapExport
   :members:
```

---

## The reader

The counterpart of {class}`~zpfwire.capture.CaptureReader`: it selects,
merges, defragments and parses, and yields the same
{class}`~zpfwire.capture.PacketView` objects.

```{eval-rst}
.. autoclass:: zpfwire.packets.PacketRecordReader
   :members:
```

---

## The sink

Where a tracker's session goes when the input is a `.zpf`: a session of
python-zipline's sessionization stage, whose records cite input packets.

```{eval-rst}
.. autoclass:: zpfwire.packets.PacketSink
   :members:
```

---

## Reasons and skip keys

```{eval-rst}
.. autodata:: zpfwire.packets.REASON_UNDECODABLE
```

```{eval-rst}
.. autodata:: zpfwire.packets.SKIP_FRAGMENTED_UDP
```
