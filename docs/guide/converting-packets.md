# Converting decoded packets

A stage that decrypts a tunnel — WireGuard, ESP, OpenVPN, anything a Zipline
decode stage opens — leaves its inner traffic as **records, not a capture**:
one record per inner IP packet.  {func}`~zpfwire.packets.packets_to_zpf`
turns those records into the sessions inside them, with the same reassembly
a capture gets, and writes a transport-layer `.zpf` whose every record cites
the input packets it was built from.

```python
import zpfwire

stats = zpfwire.packets_to_zpf("packets.zpf", "inner.zpf")
print(stats.summary())
```

From the command line it is `convert`, which tells a `.zpf` from a capture by
its first bytes:

```bash
zpfwire convert packets.zpf -o inner.zpf
```

## Where it sits

This is the third hop of the specification's worked example, *a decrypted
tunnel* (`vectors/tunnel/`, vendored in this repository's tests):

```
wg.pcap ──[zpfwire convert]──▶ outer.zpf ──[decrypt]──▶ packets.zpf
                               UDP datagrams            inner IP packets
                               capture / transport      zpf / decoded

packets.zpf ──[zpfwire convert]──▶ inner.zpf ──[http/1.1]──▶ http.zpf
                                   TCP and UDP flows        messages
                                   zpf / transport          zpf / decoded
```

The point of keeping the decrypted packets in `.zpf` rather than writing them
to a pcap and converting that is the chain: a loss in `http.zpf` traces back
through `inner.zpf`'s sequence hole and `packets.zpf`'s failed decryption to
ciphertext in `outer.zpf`.  A pcap would cut it.

When the goal is Wireshark rather than the chain, export the packets
instead — {func}`~zpfwire.packets.packets_to_pcap`, or `zpfwire pcap` (see
{doc}`../cli/pcap`).  The same records are selected, in the same order,
and written exactly as stored; the pcap cites nothing.

## Which records are packets

A record is a packet when its `content_type` says so.  The default selects
both of the format's own labels, which since spec `0.22` mean one packet
whichever decoder wrote them:

| Label | Parsed as |
|-------|-----------|
| `net:ip` | One IPv4 or IPv6 packet, `LINKTYPE_RAW` |
| `net:ethernet` | One Ethernet frame without its FCS, `LINKTYPE_ETHERNET` |

A decoder that labels its packets with a type of its own — zipline-kober's
WireGuard decode writes `dec:ip-packet` — is selected by name:

```bash
zpfwire convert packets.zpf -o inner.zpf --content-type dec:ip-packet
```

Records under any other label are parsed as raw IP unless `--link-type`
(`link_type=`) says otherwise.  When nothing is selected the summary's
`input` line says so — `181 records, 0 selected as packets` — and `convert`
prints a note naming `--content-type`.

Bytes past the IP datagram's declared length are ignored, as a capture's
Ethernet padding is: a decryptor that keeps a tunnel's own padding in the
record loses nothing.

## What the output says about every input byte

The output is a derived file, so it owes the specification's **coverage
guarantee**: every byte of every input stream is cited by a record's spans or
named by an Undecoded block, never both.  The stage writing it
(python-zipline's `sessionize_stage`) checks that and fills in what nobody
claimed; zpfwire supplies the parts only it knows.

- **Cited**: every packet whose bytes, or whose flags, reached a record — a
  data segment, the SYN behind the SYN record, a FIN whose flag closed a run.
  A packet is cited **whole**, headers included, because the headers are what
  placed its bytes in the stream; that is the specification's test,
  *correspondence, not proximity*, and what the vector's `inner.zpf` does.
- **Marked with the reason it was discarded**: a packet reassembly threw away
  entirely carries the reason it would carry on a capture —
  `duplicate-discarded`, `overlap-discarded`, `late-arrival` and its two
  refinements, `paws-rejected`, `bad-checksum` (see {doc}`provenance`).  A
  packet only partly discarded is cited, since part of it reached a record.
- **Marked `undecodable`**: a record labelled as a packet whose IP or
  transport header did not parse, or the fragments of a datagram that never
  completed, with a `comment` saying which.
- **Left as `skipped`**: everything else nobody claimed — records that are not
  packets (a field-granular decode's header fields), pure ACKs, packets of a
  transport not asked for or of a filtered flow.  None of them carries content
  of a stream this file produces.

The input's own Undecoded blocks are not copied: they name a file further up
the chain, and following them is a consumer's walk, not this stage's.

## Records join across the input's seams

A tunnel decryptor's output is often a **unit sequence** — every record its
own unit, declared `adjacency = units` — or declares a Discontinuity where a
datagram failed to decrypt.  Either says the input's records do not join.
A TCP reassembler joins them anyway, and is right to: its sequence numbers
prove which bytes are contiguous, and a packet lost between two of a flow's
segments shows up as a hole no record covers.  Spec `0.22` says exactly that —
a transport record carrying `seq_start` **may** cite several input units, or
cross an input Discontinuity (zipline#152).  So a `.zpf` input coalesces the
way a capture does, and over every fixture in this repository's tests the
two give the same records.

A `decrypt-failed` datagram upstream therefore appears here as a sequence
hole, as a lost packet would in a capture.  There is no block to carry the
upstream reason: a transport stream may hold no Discontinuity, and the failed
region is a range of `outer.zpf`, not of this file's input.  The chain stays
walkable all the same — the records either side of the hole cite the
packets either side of the input's break.

UDP has no sequence numbers, so a UDP record cites one packet.  A UDP datagram
**reassembled from IP fragments** would cite several, which no record without
`seq_start` may; its fragments are marked `undecodable` and counted under
`SKIP_FRAGMENTED_UDP` (zipline#166).  Fragmented TCP is one record.

## Order

A decrypting stage typically writes one participant per tunnel direction and
stores one direction's records before the other's, so the input's stored
order is not wire order.  The reader merges every input stream by timestamp;
two records in different streams sharing a timestamp are taken in stream
order, since a `.zpf` records no order between them.  Within one input
stream, records are read in stored order — which a stage writing packets in
time order, as a decryptor does, satisfies.

## Sessions that end and resume

A conversation that falls silent past `--session-timeout` and resumes, or
that crosses a `capture-gap`, gets a second session on the same key, exactly
as a capture conversion writes it: the first ends `timeout` or `capture-gap`,
and the second follows on the same key — after a `capture-gap` with no `isn`,
so the stream resumes at its first captured byte.
