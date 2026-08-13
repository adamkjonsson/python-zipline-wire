# Causal order

By default records are stored in **capture order**, which is not the order
events happened.  Two packets recorded a microsecond apart may have crossed on
the wire, and a file that stores them as recorded is asserting something the
capture never established.

`sequenced=True` stores each TCP session in a valid causal linearization
instead, and marks it `SEQUENCED` so a reader may act on the order:

```python
stats = zpfwire.capture_to_zpf("capture.pcap", "out.zpf", sequenced=True)
```

```bash
zpfwire convert capture.pcap -o out.zpf --sequenced
```

## What the flag promises

`SEQUENCED` says the stored order *is* a valid causal linearization: no record
appears before something it depends on.  Concretely, and checkably:

* each participant's `seq_start` values are non-decreasing, and
* no record appears after a peer record that already acknowledged its bytes.

The reader-side check of exactly that is `zpf.verify_sequenced`:

```python
import zpf

with zpf.open("out.zpf") as reader:
    for session in reader.sessions():
        if session.sequenced:
            zpf.verify_sequenced(
                session.records(),
                participant_count=len(session.participants),
            )
```

It raises if the promise was not kept.  Note what is *not* checked:
timestamps.  A stored order may run backwards in time — a sequenced order is a
causal claim, not a chronological one.

## Why a TCP session needs no basis

A session is **hint-ful** when its records carry `seq` and `ack`.  Those are
exactly what establishes what happened before what, so a hint-ful session's
causal order follows from the records themselves and needs no external
justification.

A **hint-less** session — one with no `seq`/`ack` at all — has to say what its
order rests on, in `sequenced_basis`.  This is where an obvious implementation
goes wrong, and the reason is worth knowing.

## The empty-session trap

A TCP session is hint-ful only if it *has* records.  A conversation of pure
acknowledgements produces none — and a session with no records carries no
`seq`/`ack`, so it is hint-less however TCP it is.  Marking it `SEQUENCED`
without a basis is a semantic violation, and the writer will refuse it:

```
Session(session 1) is SEQUENCED and carries no seq/ack on any record,
so it must record what its order rests on in sequenced_basis
```

This is not a corner case: three of the four sessions in the project's
`http_example.pcapng` fixture are exactly this.

The flag is written on the Session Descriptor, *before* any record exists, so
a producer cannot know which kind the session will be.  The specification's
answer is to record what you **rely on** rather than what turns out to apply —
and zpfwire's files set `SINGLE_CLOCK`, one capture being one tap, which
supplies a sound basis for any session that turns out hint-less.  So every
sequenced session declares:

```python
sequenced_basis="clock"
```

which is redundant for the hint-ful ones and correct for the rest.

## The cost

A causal order needs **both directions in hand**, so a sequenced session is
buffered until it ends.  That is unbounded for the session's lifetime.

This is the whole reason the flag is opt-in.  The format's selling point is
streaming, and this trades it away: a long-lived connection carrying a large
transfer will hold all of it in memory before anything is written.

Mitigations, in the order worth trying:

* Convert without `sequenced` unless a consumer actually needs the ordering.
* Lower `session_timeout` so long-lived conversations are split into several
  sessions, each buffered and released separately.
* Filter to the conversations you care about.

## UDP sessions are not marked

```python
stats = zpfwire.capture_to_zpf("dns.pcap", "out.zpf", sequenced=True)
# UDP sessions in the output: sequenced == False
```

A datagram carries no `seq` or `ack`, so a UDP session is hint-less and its
order would rest on the clock alone.  That is arguably defensible given
`SINGLE_CLOCK`, but it is a different claim from the one this flag was added
to make, and zpfwire does not make it.  If you need it, the pieces are all
present — see the note in `PLAN.md`.

## What sequencing does not change

Reordering storage does not alter either direction's byte stream:

```python
plain = zpfwire.capture_to_zpf("capture.pcap", "a.zpf")
seq   = zpfwire.capture_to_zpf("capture.pcap", "b.zpf", sequenced=True)
# every participant's concatenated payload is identical in both
```

The streams are the data; the stored order is a presentation choice.  Record
count, payload bytes, and every loss counter come out the same.

## Interaction with discontinuity

Buffering a session for reordering is incompatible with a positional block, so
`discontinuity()` is refused while sequencing is on.  This costs zpfwire
nothing — a transport stream expresses its gaps in its offsets and never emits
one — but it is worth knowing if you extend {class}`~zpfwire.flow.FlowTracker`
with your own.
