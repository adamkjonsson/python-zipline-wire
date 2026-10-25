# `zpfwire convert`

Convert a capture, or a `.zpf` of packets such as a decrypted tunnel's, into a
transport-layer `.zpf` file.  Which input it is comes from its first bytes;
the second is under {ref}`from-a-zpf` below.

```bash
zpfwire convert capture.pcap -o capture.zpf
```

```
packets      219
converted    219
sessions     1
records      135 (103 pure ACKs)
payload      78901 bytes
overlap      8875 bytes (retransmitted, discarded)
ts fallback  12 repeat(s) treated as retransmitted without timestamp evidence (absent: 12)
undecoded    12 region(s) cited
```

The output is one session per conversation, two participants per session, and
one record per run of contiguous stream bytes.  What each of those means in
specification terms is in {doc}`../reference/zpf-mapping`.

## Output

| Flag | What it does |
|------|--------------|
| `-o`, `--output PATH` | File to write. Required. |
| `--jsonl` | Write the JSON-Lines projection instead of the binary container |
| `-q`, `--quiet` | Do not print the summary |

`--jsonl` writes the same content through the format's other face.  It is
diffable and greppable, which makes it the better choice when you want to
*look* at what was produced:

```bash
zpfwire convert capture.pcap -o capture.jsonl --jsonl
```

## Choosing what to convert

| Flag | What it does |
|------|--------------|
| `--no-tcp` | Skip TCP conversations |
| `--no-udp` | Skip UDP conversations |

Passing both is an error — it would leave nothing to convert.  Packets
excluded this way are counted under `tcp-not-requested` or
`udp-not-requested`, so the summary still accounts for every packet.

The same rule refuses a capture whose **link type packeteer cannot decode**:
nothing in it can be reached, so rather than write a valid, empty file and
report `skipped N (unsupported-linktype)` at the end, `convert` says so and
exits `1`.  `zpfwire info` reports the same fact and continues, since
reporting is its job; and the API still writes the empty file if asked —
{class}`~zpfwire.capture.CaptureReader` exposes the fact as
`link_type_supported`, and {func}`~zpfwire.convert.convert` keeps its
every-packet contract.

```
$ zpfwire convert weird.pcap -o weird.zpf
Error: link type 999 is one packeteer cannot decode, so every packet in the capture is skipped: nothing to convert
```

The filtering flags described in {doc}`index` apply here too, and compose with
these: `--no-udp --dst-port 443` keeps only TCP traffic to port 443.

(from-a-zpf)=

## From a `.zpf` of packets

```bash
zpfwire convert packets.zpf -o inner.zpf
zpfwire convert packets.zpf -o inner.zpf --content-type dec:ip-packet
```

The input is a `.zpf`, binary or JSON-Lines, whose records are packets: the
inner traffic a decryption stage leaves.  The output is the sessions inside
it, each record citing the input packets it came from — see
{doc}`../guide/converting-packets`.  Every other flag on this page applies
unchanged, filters included, to the inner packets.

| Flag | What it does |
|------|--------------|
| `--content-type LABEL` | The label that makes a record a packet. The default selects `net:ip` and `net:ethernet`, the format's own; pass a decoder's private label, such as zipline-kober's `dec:ip-packet`, to select that instead |
| `--link-type N` | How to parse records under a label outside `net:`; raw IP (`101`) if omitted. A `net:` label names its own, and one that disagrees is refused |

Refused with a `.zpf`, exit `1`: `--tick-hz`, since the file states its own.
`--content-type` is refused with a capture.  `--jsonl` writes the JSON-Lines
projection, as it does for a capture.  The summary gains a first line counting the input's records:

```
input        181 records, 33 selected as packets
packets      33
...
```

When no record was selected, a note on stderr says so and names
`--content-type`.

## Reassembly policy

These flags decide **which bytes reach the output**.  They are not performance
tuning: the specification makes committing a gap irreversible, so once a record
has been written past missing bytes, those bytes may never be written even if
they turn up later.  These settings are what decide when that happens.

| Flag | Default | What it decides |
|------|---------|-----------------|
| `--reorder-window BYTES` | `262144` | How much out-of-order data a direction may hold before the oldest gap is committed. `0` disables buffering entirely. |
| `--flush-timeout SECONDS` | `5.0` | How long a gap may stay unfilled, measured in capture time, before it is committed |
| `--overlap {favor-old,favor-acked}` | `favor-old` | Which copy wins when retransmitted bytes disagree with bytes already accepted: the first seen, or the one the receiver's acknowledgement echoed — see {doc}`../guide/reassembly` |
| `--session-timeout SECONDS` | `300.0` | Silence after which a conversation is closed and a later packet starts a new session |
| `--no-coalesce` | off | Emit one record per segment instead of one per contiguous byte run |
| `--no-pure-acks` | off | Fold each pure ACK's `ack` into the next data record instead of storing it as a zero-length record, as every release before `0.6.0` did. Writes exactly what `0.5.0` wrote. Smaller and faster to write, since there are about as many pure ACKs as data segments (19% less output and 23% less time on a 4,140-packet HTTP capture), at the cost of the ordering and timing they give readers — see {doc}`../guide/reassembly` |
| `--checksum {ignore,drop}` | `ignore` | What to do with a TCP segment whose checksum does not verify. `drop` discards it as a receiver would, leaving the retransmission to supply the bytes. A UDP datagram is kept under either, and counted: a UDP stream could not show one missing |

All seven are hashed into the file's decoder descriptor as a `params_digest`,
so a `.zpf` records the policy that produced it and a conversion can be
reproduced.  `--no-pure-acks` is recorded by its absence, so an opted-out
file declares the digest `0.5.0` declared for the same policy.  {doc}`../guide/reassembly` works through what each one costs.

## Causal order

| Flag | What it does |
|------|--------------|
| `--sequenced` | Store each TCP session in a valid causal linearization and mark it `SEQUENCED` |

By default records are stored in capture order, which is not the order events
happened — two packets recorded a microsecond apart may have crossed on the
wire.  `--sequenced` stores an order a reader may actually rely on.

The cost is memory: a causal order needs both directions in hand, so each
session is buffered until it ends.  That is unbounded for the session's
lifetime, which is why it is opt-in.  UDP sessions are never marked; see
{doc}`../guide/ordering`.

## Reading the summary

```
packets      219        every packet the reader saw
converted    219        packets that reached a conversation
sessions     1          conversations written
records      135 (103 pure ACKs)  records written, pure ACKs among them
payload      78901 bytes  bytes that reached the output
```

Then, only when non-zero, the figures that account for what did **not** reach
the output:

| Line | Meaning |
|------|---------|
| `input` | For a `.zpf` input: its records, and how many were selected as packets |
| `filtered` | Packets excluded by a filter — deliberate, not lost |
| `skipped N (reason)` | Packets that carried no convertible stream, by reason |
| `gaps` | Places where a record was written past bytes that never arrived |
| `late bytes` | Bytes that arrived after their gap had been committed, so could not be written |
| `  reordered` | Of those, originals the network delayed — a wider window would have kept them |
| `  resent` | Of those, resends of a loss, recovered after the gap closed — nothing would have |
| `overlap` | Retransmitted bytes discarded because that range was already accepted |
| `duplicates` | Segments that were copies of an earlier transmission — the capture point saw them twice — and how much of the file that is |
| `paws` | Bytes rejected because their clock was older than the last accepted in order: an old segment from before a wrap |
| `wrap` | Holes wider than 2³⁰ bytes crossed by the clock, each splitting the session |
| `acked` | Under `--overlap favor-acked`: ranges that took the receiver's copy, and contested bytes decided without ack evidence |
| `ts fallback` | Repeats treated as retransmissions because the Timestamps option could not judge them, and why |
| `bad cksum` | Packets whose transport checksum did not verify, whether or not they were dropped |
| `dropped` | TCP payload bytes discarded under `--checksum drop` |
| `undecoded` | Regions of the capture cited as reaching no record |
| `uncited` | Discarded bytes whose place in the capture could not be named |

The rule these enforce is that **every byte is either written or counted**.
`overlap` and `late bytes` are then cited as `Undecoded` regions wherever
their position in the capture file can be named — see {doc}`../guide/provenance`.

When bytes were lost, a note goes to stderr and the exit status stays `0`:

```
$ zpfwire convert lossy.pcap -o lossy.zpf
packets      193
converted    193
sessions     1
records      105 (95 pure ACKs)
payload      71617 bytes
gaps         6
Note: some bytes never reached the output. Raise --reorder-window or
--flush-timeout to wait longer.
```

That is a real outcome of the policy rather than a failure, which is why it is
a note rather than an error.  If those bytes matter, raise the limits and
convert again.

## Verifying the result

The `zpf` CLI reads what this writes:

```bash
zpf validate --strict capture.zpf     # conformance
zpf cat capture.zpf                   # human-readable dump
```

`validate --strict` is the check worth wiring into a pipeline.  Every capture
in the project's test suite is asserted to pass it.

## From Python

```python
import zpfwire

stats = zpfwire.capture_to_zpf(
    "capture.pcap",
    "capture.zpf",
    options=zpfwire.ReassemblyOptions(reorder_window=0),
    udp=False,
    sequenced=True,
)
print(stats.summary())
```

See {doc}`../guide/converting`.
