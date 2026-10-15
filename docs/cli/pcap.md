# `zpfwire pcap`

Export the packet records of a `.zpf` — a decrypted tunnel's inner traffic,
say — to a pcap, for Wireshark and the tools that read one.

```bash
zpfwire pcap packets.zpf -o inner.pcap
zpfwire pcap packets.zpf -o inner.pcap --content-type dec:ip-packet
```

```
input        181 records, 33 selected as packets
written      33 packets, link type 101
```

This is an **export for analysis**, not a step in the provenance chain: a
pcap has nowhere to say which input record a packet came from, so the file
cites nothing.  To keep the chain, `zpfwire convert` the same `.zpf` instead
— see {doc}`../guide/converting-packets`.

## What is written

- **The same records `convert` selects**, merged across the input's streams
  into time order: a decryptor typically stores one tunnel direction before
  the other.
- **Each record's bytes exactly as stored.**  A decryptor that keeps its
  tunnel's padding after the IP datagram keeps it here, and Wireshark shows it
  as a trailer.
- **Fragments as the fragments they are.**  Wireshark reassembles them.
- **The link type the label names**: `101` (raw IP) for `net:ip` or any label
  outside `net:`, `1` (Ethernet) for `net:ethernet`.  A selection holding
  both is refused, since a pcap has one link type; pass `--content-type` to
  export one of them.
- **Microsecond timestamps**, or nanosecond when the input counts finer.

## Flags

| Flag | What it does |
|------|--------------|
| `-o`, `--output PATH` | The pcap to write. Required. |
| `--content-type LABEL` | The label that makes a record a packet; the default selects `net:ip` and `net:ethernet` |
| `--link-type N` | The link type of a label outside `net:`; raw IP (`101`) if omitted |
| `-q`, `--quiet` | Do not print the summary |

The filtering flags described in {doc}`index` apply too, to the packets
themselves.  A filter can only judge a record that is one whole TCP segment or
UDP datagram, so with a filter given, fragments and records of other
protocols are left out, and counted on a `filtered` line.

A capture is refused: it is a pcap already.
