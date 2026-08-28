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

Full documentation lives in `docs/` — build it with `cd docs && make html`.
This README is the short version.

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

# Store each TCP session in causal order rather than capture order
zpfwire convert capture.pcap -o capture.zpf --sequenced
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
records      10
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
| `--checksum {ignore,drop}` | whether to discard a packet whose transport checksum does not verify |

These are hashed into the file's decoder descriptor, so a `.zpf` records the
policy that produced it.

`--checksum drop` is worth knowing about: a corrupt segment is normally
retransmitted cleanly, and the damaged copy arrives first, so the default
keeps bytes no endpoint ever accepted. Dropping is not the default because
checksum offload makes a capture taken on a sending host show wrong checksums
for traffic that was fine on the wire.

A TCP hole needs no marker in the file: `seq_start` is the absolute wire
sequence number, so a gap is visible as arithmetic. (`Discontinuity` blocks are
for decoded layers, not this one.)

Bytes that *do* exist in the capture and reach no record are a different
matter, and nothing else in the format can express them — so a discarded
retransmit is written as an `Undecoded` block naming its byte range in the
capture file:

```
overlap      8875 bytes (discarded)
undecoded    12 region(s) cited
```

## Causal order

By default records are stored in capture order, which is not the same thing as
the order events happened: two packets recorded a microsecond apart may have
crossed on the wire.

`--sequenced` stores each TCP session in a valid causal linearization instead
and marks it `SEQUENCED`, so a reader may act on the order. A TCP session is
*hint-ful* — the order follows from `seq` and `ack` — so this needs no guesswork.

The cost is memory: a causal order needs both directions in hand, so a session
is buffered until it ends. That is unbounded for the session's lifetime, which
is why it is opt-in in a format whose point is streaming.

## Not yet

- **Application decoding.** Deliberately out of scope for now. It is a
  *second* file, produced from this one with `zpf.decode_stage(...)`, and the
  clean transport-layer output here is what makes that possible.
- **Sequenced UDP sessions.** A UDP session carries no `seq`/`ack`, so its
  order rests on something else and claiming it is a separate judgement.
- **SACK-aware loss inference.** TCP options are parsed and carried on each
  packet, but the reassembler does not yet use them.

`PLAN.md` tracks these.

## Development

```bash
.venv/bin/pytest                                    # tests
ruff check src/ tests/ docs/                        # lint, must be silent
.venv/bin/sphinx-build -W docs docs/_build/html     # docs, warnings are errors
```

Capture fixtures in `tests/captures/` are copied from packeteer's `testcases/`.
Every test asserts that what was written reads back through `zpf.open` with no
diagnostics — a file that does not is not a conversion.

One purpose of this project is to pressure-test its two dependencies, so gaps
found here are filed as issues against them rather than worked around here. See
`CLAUDE.md`, and `docs/internals/` for how the whole thing fits together.

## Licence

MIT.
