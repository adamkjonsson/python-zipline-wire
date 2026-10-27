# Choosing a policy from evidence

The reassembly options decide which bytes reach the output, and some of them
trade one kind of error for another.  A wider `reorder_window` waits longer
for a hole to fill, and holds more in memory.  `favor-acked` swaps in the copy
the receiver kept, and holds every run until the receiver's ack says which
that was.  The defaults are reasonable for most links, but they are guesses
about *your* link.  `zpfwire.fidelity` replaces the guess with a measurement.

The method is to describe a conversation shaped like your traffic, let the
network do to it what yours does, and compare policies on what each one makes
of it.  packeteer generates the traffic, so the truth is known exactly: every
byte each side sent, and what happened to every packet on the way.

## One question, two policies

A bulk upload over a link that loses 10% of its segments, where the sender
resends each after an RTO of one second, RFC 6298's initial value:

```bash
zpfwire fidelity --messages c2s:1048576 --packet-loss 0.1 --retransmit-lost \
    --retransmission-timeout 1 --seeds 4
zpfwire fidelity --messages c2s:1048576 --packet-loss 0.1 --retransmit-lost \
    --retransmission-timeout 1 --seeds 4 --reorder-window 1048576
```

| Policy | Fidelity, median / worst | Recovery, median / worst | Wrong bytes |
| --- | --- | --- | --- |
| defaults (`reorder_window` 256 KiB) | 0.9219 / 0.9102 | 0.9219 / 0.9102 | 333,040 `missing:dropped` |
| `--reorder-window 1048576` | 1 / 1 | 1 / 1 | none |

Recovery below 1 is the signal.  Every wrong byte was in the capture, and
the reassembler gave up on it: a second of data at this rate is more than
256 KiB, so the window commits each hole before its resend arrives.  The
wider window keeps every byte, at the cost of holding up to 1 MiB per
direction.  Whether that cost is worth paying is your call, but now it is
made knowing what it buys.

## The same from Python

```python
from zpfwire import ReassemblyOptions
from zpfwire.fidelity import Impairments, Scenario, evaluate, parse_shape

link = Scenario(
    shape=parse_shape("c2s:1048576"),
    impairments=Impairments(packet_loss_probability=0.1, retransmit_lost=True,
                            retransmission_timeout=1.0),
)
for window in (262_144, 1_048_576):
    e = evaluate(link, ReassemblyOptions(reorder_window=window), seeds=range(4))
    print(window, min(m.total.recovery for m in e.scored))
```

{func}`~zpfwire.fidelity.evaluate` returns an
{class}`~zpfwire.fidelity.Evaluation`.  Its `scored` measurements each carry
a {class}`~zpfwire.fidelity.ByteScore` per direction, with every wrong byte
attributed to its cause, and an {class}`~zpfwire.fidelity.Accounting` of
whether the file told the truth about itself.  `report()` is the Markdown
the command prints, and `jsonl()` one line per seed.

## Reading a result honestly

**Fidelity against recovery.** Fidelity is what a reader of the file gets;
recovery is what the reassembler made of what it was given.  A loss nobody
resent lowers fidelity and leaves recovery at 1: no policy could have saved
those bytes, and none should be chosen to.  Choose on recovery.

**Look at what was realised.** Each run's row says what the network actually
did: so many `RETRANS`, `CORRUPT` or `STRAY` packets, so many bytes lost.  At
a low rate, a seed can exercise nothing, and a perfect score from a run in
which nothing happened says nothing about the policy.  Use enough seeds, and
a rate that makes the impairment happen.

**The accounting must be clean.** If a file misstates the conversion, or
does not read back clean, that is a bug in zpfwire whatever the scores say.
Please report it, with the command line that produced it: the same flags
reproduce it exactly.

**It is a model of your link, not your link.** packeteer's traffic is
regular where real traffic is not, and its impairments are independent where
real ones come in bursts.  A policy that wins here is better supported than a
guess, not proven.  Where you have a real capture of the problem, convert it
under both policies and compare the stats:
`acked_fallback_bytes`, `late_bytes` and `gaps` say what each policy gave up.

## What to try

| If your link… | Measure | Against |
| --- | --- | --- |
| resends late (a long RTO, a satellite hop) | `--retransmission-timeout` at your RTO | `--reorder-window`, `--flush-timeout` |
| corrupts payloads that checksum offload hides | `--payload-corruption` | `--overlap favor-acked`, `--checksum drop` |
| acknowledges late (delayed ACK past `flush_timeout`) | `--retransmission-timeout` past 5 s | `--overlap favor-acked --acked-hold` |
| may carry forged segments | `--stray-packets`, with and without `--stray-timestamps` | `--require-timestamps`, `--overlap favor-acked` |
| is mirrored, so the capture sees packets twice | `--duplicate` | the defaults should already score 1 |

The order and timing of messages, and UDP, are measured by this project's
own tool, `tools/fidelity.py`, but not yet by `zpfwire.fidelity`.  Their
definitions are still settling, and a public promise waits until they have
survived a release unchanged.
