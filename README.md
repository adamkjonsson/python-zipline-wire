# zpfwire

Turn network captures into [Zipline Payload Format](https://github.com/adamkjonsson/zipline)
(`.zpf`) files — TCP reassembly included.

A capture file answers *what was on the wire*. A `.zpf` answers *what did they
say*. `zpfwire` is the step between: it reads a pcap, groups packets into
conversations, reassembles each direction's byte stream, and writes the result
as sessions, participants and records.

It is glue, and deliberately so:

- [**packeteer**](https://github.com/adamkjonsson/packeteer) parses the capture.
- [**zpf**](https://github.com/adamkjonsson/python-zipline) writes the format.
- `zpfwire` does the part neither can — flow tracking, TCP reassembly, and the
  mapping onto the specification's model.

**Status: early.** The format itself is `0.x` and says it is not ready for
production; this is a first implementation against `0.16`.

## Install

The two dependencies are not on PyPI, so check them out next to this repo:

```bash
git clone https://github.com/adamkjonsson/packeteer.git
git clone https://github.com/adamkjonsson/python-zipline.git
git clone https://github.com/adamkjonsson/python-zipline-wire.git

cd python-zipline-wire
python -m venv .venv
.venv/bin/pip install -e . -r requirements.txt
```

## Use it

```bash
# What is in this capture?
zpfwire info capture.pcap

# Convert it
zpfwire convert capture.pcap -o capture.zpf

# The readable JSON-Lines projection instead of the binary container
zpfwire convert capture.pcap -o capture.jsonl --jsonl

# Just one subnet's HTTPS traffic
zpfwire convert capture.pcap -o https.zpf --dst-port 443 --src 10.0.0.0/24
```

```python
import zpfwire

stats = zpfwire.capture_to_zpf("capture.pcap", "capture.zpf")
print(stats.summary())
```

Everything the CLI does is available from the API; the CLI is a thin wrapper
over it.

## What it writes

A **capture-sourced, transport-layer** file — the top-left cell of the
specification's provenance/layer table. Concretely:

| Block | What goes in it |
|---|---|
| File Header | tick rate from the capture, `single_clock` (one capture is one tap) |
| Source | `kind=capture`, the path, a SHA-256 digest, the link type |
| Decoder | `tcp-reassembly`, `output_layer=transport`, plus a digest of the reassembly policy |
| Session | one per conversation, both directions together |
| Participant | one per endpoint, with `isn` and `tcp_role` when the handshake was captured |
| Record | a reassembled byte run with `seq_start` and `ack`; UDP datagrams carry the `message` flag |
| Session End | `fin`, `rst`, `timeout` or `capture-end` |

Reassembly counts as a decoder in zipline's vocabulary — that is why the
Decoder block is there, and why it declares `output_layer = transport` rather
than `decoded`. It is also the only place the reassembly policy can be
recorded, which is what makes a conversion reproducible.

## Nothing is lost quietly

The specification makes one rule that shapes everything: **committing a gap is
irreversible.** Once a record has been written past missing bytes, those bytes
may never be written, even if they turn up later.

So the reassembler has an explicit, bounded policy for how long it waits, and
every byte that does not reach the output is counted:

```
$ zpfwire convert lossy.pcap -o lossy.zpf
packets      193
converted    193
sessions     1
records      8
payload      71617 bytes
gaps         6
Note: some bytes never reached the output. Raise --reorder-window or
--flush-timeout to wait longer.
```

| Flag | What it decides |
|---|---|
| `--reorder-window BYTES` | how much out-of-order data to hold before giving up on a gap |
| `--flush-timeout SECONDS` | how long a gap may stay unfilled |
| `--overlap {favor-old,favor-new}` | which copy wins when retransmitted bytes disagree |
| `--session-timeout SECONDS` | silence after which a conversation is closed |
| `--no-coalesce` | one record per segment instead of per contiguous byte run |

These are hashed into the file's decoder descriptor, so a `.zpf` records the
policy that produced it.

A TCP hole needs no marker in the file: `seq_start` is the absolute wire
sequence number, so a gap is visible as arithmetic. (`Discontinuity` blocks are
for decoded layers, not this one.)

## Not yet

- **Application decoding.** Deliberately out of scope for now. It is a
  *second* file, produced from this one with `zpf.decode_stage(...)`, and the
  clean transport-layer output here is what makes that possible.
- **Sequenced sessions.** Records go out in capture order and the session is
  not marked `SEQUENCED`. Committing to a causal linearization is planned.
- **IP defragmentation.** Fragments are counted and skipped, not reassembled.
- **Bounded memory.** The capture is read whole; there is no streaming reader
  yet.

`PLAN.md` tracks these with the upstream issues they depend on.

## Development

```bash
.venv/bin/pytest        # tests
ruff check src/ tests/  # lint, must be silent
```

Capture fixtures in `tests/captures/` are copied from packeteer's `testcases/`.
Every test asserts that what was written reads back through `zpf.open` with no
diagnostics — a file that does not is not a conversion.

One purpose of this project is to pressure-test its two dependencies, so gaps
found here are filed as issues against them rather than worked around here. See
`CLAUDE.md`.

## Licence

MIT.
