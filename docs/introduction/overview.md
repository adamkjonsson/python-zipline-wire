# Overview

zpfwire converts a network capture into a **Zipline Payload Format** file.
A pcap holds packets; a `.zpf` holds *conversations* — the byte streams those
packets carried, grouped by who was talking to whom, with the retransmits
resolved and the reordering undone.

```bash
zpfwire convert capture.pcap -o capture.zpf
```

```python
import zpfwire

stats = zpfwire.capture_to_zpf("capture.pcap", "capture.zpf")
print(stats.summary())
```

## The one fact that settles everything else

The specification classifies every `.zpf` on two axes: where its data came
from (**provenance**) and how far up the stack it has been decoded
(**layer**).  Everything zpfwire writes sits in one cell of that table —
**capture-sourced** and **transport-layer** — and most of the design follows
from saying so out loud.

| Axis | Value | What it settles |
|------|-------|-----------------|
| Provenance | `capture` | The input is a pcap, not another `.zpf`. There is no upstream stream to reference, so `spans` cannot be used and `Undecoded` blocks address byte offsets in the capture file. |
| Layer | `transport` | Records are byte runs, not parsed messages. `content_type` is forbidden, and a gap in a stream needs no marker — absolute sequence numbers make it visible by arithmetic. |

The corollaries are worked through in {doc}`../reference/zpf-mapping`.  What
matters at this level is that zpfwire does **not** decode application
protocols, and this is not an omission.  Application decoding produces a
*second* file, derived from this one by a decode stage; the clean
transport-layer output here is its input.

## What zpfwire is not

It owns no file format and no packet parser.  It is glue between two
libraries that do not know about each other:

| Project | Its job here |
|---------|--------------|
| **packeteer** | Reads the capture and parses each packet, including reassembling IP fragments. |
| **zpf** (python-zipline) | Writes and validates the `.zpf` container against the specification. |

What is left over — grouping packets into conversations, reassembling TCP byte
streams, and mapping the result onto the specification's
session/participant/record model — is zpfwire.

That division is deliberate rather than incidental.  packeteer is a stateless
per-packet toolkit, while the shape of reassembled output is dictated by the
payload format: byte runs rather than segments, a record stamped with its
*last* contributing packet, ascending sequence order per participant, and gap
commitment that cannot be taken back.  Those are the format's rules, so the
reassembler that obeys them lives on this side of the seam.

## What a conversion produces

One session per conversation, two participants per session, and a record for
each run of contiguous bytes:

```
$ zpfwire convert retransmission.pcap -o out.zpf
packets      219
converted    219
sessions     1
records      32
payload      78901 bytes
overlap      8875 bytes (discarded)
undecoded    12 region(s) cited
```

Every figure after the first two exists so that nothing is lost quietly.  A
retransmit whose bytes were already accepted is discarded — and then *cited*,
as a region of the capture file that reached no record, because nothing else
in the format can express that.  See {doc}`../guide/provenance`.

## Where to go next

| If you want to | Read |
|----------------|------|
| Install it | {doc}`installation` |
| Convert a capture from the command line | {doc}`../cli/index` |
| Drive it from Python | {doc}`../guide/index` |
| Know which spec construct something becomes | {doc}`../reference/zpf-mapping` |
| Work on zpfwire itself | {doc}`../internals/index` |
