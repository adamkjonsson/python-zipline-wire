# `zpfwire fidelity`

Measure a reassembly policy against TCP traffic packeteer generates.

```bash
zpfwire fidelity --payload-corruption 0.2 --seeds 5
zpfwire fidelity --payload-corruption 0.2 --seeds 5 --overlap favor-acked
```

Each run generates the conversation `--messages` describes, with packeteer,
under the impairments the flags ask for and one seed.  It converts the
capture under the reassembly options given, exactly as `convert` would, and
scores the `.zpf` against what each side actually sent.  The report is
Markdown, on stdout.  The same flags give the same report, byte for byte,
so two policies can be compared by running both.

TCP only.  The command is a thin wrapper over
{func}`~zpfwire.fidelity.evaluate`; see {doc}`../guide/choosing-a-policy`
for the method, and {doc}`../api/fidelity` for the API.

## Reading the report

The first run above, `favor-old` against corrupted segments that are then
resent clean:

```
## Scores

5 of 5 runs scored.

| | median | worst |
| --- | --- | --- |
| fidelity: correct ÷ sent | 0.9998 | 0.9998 |
| recovery: correct ÷ captured | 0.9998 | 0.9998 |

Wrong bytes over all runs, by cause:

- substituted:corrupt: 12

Every scored file accounts for every byte it was given.

## Runs

| seed | realised | fidelity | recovery | wrong bytes | accounting |
| --- | --- | --- | --- | --- | --- |
| 0 | ACK-RECOVER 1, CORRUPT 1, RETRANS 1 | 0.9999 | 0.9999 | substituted:corrupt 1 | ok |
| 1 | ACK-RECOVER 3, CORRUPT 3, RETRANS 3 | 0.9998 | 0.9998 | substituted:corrupt 3 | ok |
…
```

**Fidelity** is correct bytes ÷ bytes sent: what a reader of the file gets.
**Recovery** is correct bytes ÷ bytes some captured copy carried: what the
reassembler made of what it was given.  A segment lost on the wire and never
resent lowers fidelity and leaves recovery at 1, since no policy could have
kept it.  A corrupted copy kept, as here, lowers both.  Scores are floored,
never rounded up to 1.

**Wrong bytes, by cause**, says why each wrong byte is wrong:

| Cause | Meaning |
|-------|---------|
| `missing:lost` | no captured packet carried it |
| `missing:dropped` | a captured packet carried it, and the reassembler let it go |
| `substituted:corrupt` | a corrupted copy was written in its place |
| `substituted:stray` | a forged segment was written in its place |
| `extra` | bytes written past what the sender sent |

**Accounting** checks that the file tells the truth about itself: every
captured byte not in a record is cited by an `Undecoded` block, the gap count
matches the holes, and the end reason matches what happened.  `ok` is the
only acceptable value.  Anything else is a bug, and the report lists it.

**Realised** is what the network did in that run: packets by kind, and bytes
lost.  A configured impairment is not a realised one.  At a low rate, a seed
may exercise nothing, and its perfect score says nothing about the policy.

A run is **void** when packeteer's output is not what it claims, and is not
scored.  A file that does not read back clean is never scored either.  It is
reported as a bug, and the command exits 1.

## Options

### The scenario

| Flag | What it does |
|------|--------------|
| `--messages SPEC` | The conversation, as `DIRECTION:LENGTH` pairs in the order sent (default: `c2s:3000,s2c:9000,c2s:800,s2c:5000`, a request and response twice) |
| `--seeds N` | How many seeds to run (default 10) |
| `--first-seed N` | The first seed (default 0) |
| `--jsonl PATH` | Also write one JSON line per seed: its scores, wrong bytes by direction and cause, accounting failures, and what was realised |

### The network

Each is the packeteer option of the same name, so a scenario moves between
the two command lines unchanged.

| Flag | What it does |
|------|--------------|
| `--psh-probability PROB` | Chance a message's last segment carries PSH (default 0.5, packeteer's; a real stack pushes nearly every write) |
| `--packet-loss PROB` | Chance a packet after the handshake is lost |
| `--retransmit-lost` | Resend each lost segment, so the stream recovers |
| `--retransmission-probability PROB` | Chance a delivered segment is resent anyway |
| `--retransmission-timeout SECONDS` | Delay before any resend (default 0.2) |
| `--payload-corruption PROB` | Chance a segment's last byte is flipped in flight, and the segment resent clean |
| `--duplicate PROB` | Chance the capture point sees a packet twice |
| `--server-rst PROB` | Chance the server resets the connection mid-stream |
| `--rst-propagation-delay SECONDS` | Delay before the client learns of a reset |
| `--stray-packets N` | Forged segments injected at real sequence numbers |
| `--stray-timing-window N` | How near its victim a stray is placed, in packets |
| `--stray-timestamps` | Stamp each stray with a Timestamps option, as the side it impersonates would |

### The policy

The reassembly options are `convert`'s, with the same names and defaults:
`--overlap`, `--reorder-window`, `--flush-timeout`, `--session-timeout`,
`--no-coalesce`, `--no-pure-acks`, `--acked-hold`, `--require-timestamps`,
`--checksum`, and `--sequenced`.  See {doc}`convert`.
