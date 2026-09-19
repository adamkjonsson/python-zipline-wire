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

## Why the order is trustworthy, and what says so

A session is **hint-ful** when its records carry `seq` and `ack`.  Those are
exactly what establishes what happened before what, so a hint-ful session's
causal order follows from the records themselves — which is why a TCP
conversation can be sequenced at all, and why the reader-side check above has
something to check against.

A session with no `seq`/`ack` is **hint-less**, and its order rests on
something outside the records.  Spec `0.19` made a decision worth knowing
about here: the flag is now a **bare assertion** either way.  A producer no
longer records what its order rests on, because a reader cannot verify the
basis any more than it can verify the order itself — so trusting the producer
for one and not the other bought nothing.  What answers the forensic question
instead is the file's build provenance: `produced_by` and `produced_at` on the
File Header, both of which zpfwire writes.

### The case that made this real

A TCP session is hint-ful only if it *has* records.  A conversation of pure
acknowledgements produces none — and a session with no records carries no
`seq`/`ack`, so it is hint-less however TCP it is.  This is not a corner case:
three of the four sessions in the project's `http_example.pcapng` fixture are
exactly that.

The flag is written on the Session Descriptor, *before* any record exists, so
a producer cannot know which kind of session it has when it has to decide.
Under spec `0.16` that was a genuine bind — the file had to justify a claim
whose ground it could not yet see, and zpfwire declared `sequenced_basis="clock"`
to cover it.  Since `0.19` there is nothing to declare, and the bind is gone
along with the option.

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

One shape `sequenced` cannot currently write at all: a direction longer than
2 GiB whose peer only acknowledges, where the format's causal check inverts
against the peer's stale recorded `ack` and the writer refuses the record.
It is filed upstream and stated in {doc}`../reference/limits`; a plain
conversion of the same capture is fine.

## UDP sessions are not marked

```python
stats = zpfwire.capture_to_zpf("dns.pcap", "out.zpf", sequenced=True)
# UDP sessions in the output: sequenced == False
```

A datagram carries no `seq` or `ack`, so a UDP session is hint-less and its
order would rest on the clock alone.  One capture is one tap, so that is
arguably defensible — but it is a different claim from the one this flag was
added to make, and not one zpfwire makes on your behalf.  If you need it, the
pieces are all present — see the note in `plans/PLAN.md`.

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
