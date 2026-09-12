# Limits

What the output does not carry, and what is not yet implemented.  Some of
these are permanent consequences of the format; others are work not yet done.
They are separated here because the difference matters when you are deciding
whether to wait.

## Permanent, by design

**No application decoding.** zpfwire produces a transport-layer file and
stops.  Decoded output is a *second* file, derived from this one by a decode
stage, and the clean transport-layer output here is its input.  This is the
whole architecture, not a gap.

**No `content_type` on records.** Forbidden at the transport layer — a byte
run has no media type.

**No `spans` on records.** A span must reference a `zpf-input` source, and a
capture-sourced file has none.  `ts_first` covers the one thing spans would
otherwise have carried.

**No `Discontinuity` blocks.** A transport stream expresses its gaps in its
offsets.  See {doc}`zpf-mapping`.

## Consequences of the reassembly policy

**Committed gaps are permanent.** Once a record is written past missing bytes,
those bytes may never be written, even if they arrive later.  This is the
specification's rule, and it is why the policy is a declared, hashed option.
Bytes lost this way are counted as `late_bytes` and cited as `late-arrival`
regions.

**Filtering below the flow level breaks streams.** A predicate that drops
segments from the middle of a connection produces gaps exactly as packet loss
would.  Filtering by address or port keeps whole conversations and is safe.

## Not yet implemented

**Sequenced UDP sessions.** A datagram carries no `seq`/`ack`, so a UDP
session is hint-less and its order would rest on the clock alone.  Defensible,
one capture being one tap, but a distinct claim from the one `--sequenced`
makes.  See {doc}`../guide/ordering`.

**A conversion run from the CLI is not byte-reproducible.**  The File Header
carries `produced_at`, a wall-clock stamp, so two conversions of one capture
differ by those bytes.  The API takes `produced_at=` to pin or omit it; the
command line has no flag for it, on the grounds that a caller who needs a
pinned stamp is scripting the conversion anyway.  The reproducibility of the
*decode* is a separate thing and is unaffected — it rests on the Decoder's
`params_digest`, which is a function of the options alone.

**SACK-aware loss inference.** TCP options are parsed and carried on every
{class}`~zpfwire.capture.PacketView` — `tcp_options.sack_blocks` tells you
which ranges the receiver actually got — but the reassembler does not consult
them.  It infers loss from arrival order and its timeouts alone, so a capture
with SACK information available is analysed as though it had none.

**The TCP Timestamps option is not read either**, and it could settle three
things the reassembler currently assumes: whether a repeated segment is a
retransmission or the same transmission seen twice (a mirror port doubles
every packet, and today each copy sets `retransmit`); whether late bytes were
a delayed original or a loss recovered after the gap was committed; and, as
PAWS, whether a segment that looks 2³¹ behind is really from after a sequence
wrap.  This is [#17](https://github.com/adamkjonsson/python-zipline-wire/issues/17),
held until a real capture exists of a retransmission carrying the option —
none does, here or in packeteer's corpus
([packeteer#149](https://github.com/adamkjonsson/packeteer/issues/149)) —
and until the format says whether `retransmit` means the sender resent or
the reassembler discarded
([zipline#142](https://github.com/adamkjonsson/zipline/issues/142)).

**A fourth thing the option could settle needs a different reassembler:**
which copy of disagreeing bytes the *receiver* kept, read from the TSval its
acknowledgement echoes.  That evidence arrives after the data it settles, by
which time the first copy has been written, so acting on it means holding
every run until the peer acknowledges it.  It is the same reason `overlap`
has one policy — see {doc}`../guide/reassembly`.

**Byte ranges for discarded fragments.** A datagram reassembled from several
IP fragments occupies several discontiguous ranges of the capture, and an
`Undecoded` block names one range.  Rather than name the wrong bytes, a
discard from such a datagram is counted as `unlocatable_bytes` and not cited.
The contributing records are known, so emitting one block per fragment is
possible; it is not done.

## Bounded by memory

**Sequenced sessions buffer.** A causal order needs both directions in hand,
so `sequenced=True` holds each session until it ends — unbounded for the
session's lifetime.  This is why it is opt-in.  See {doc}`../guide/ordering`
for mitigations.

**Reassembly buffers per direction.** `reorder_window` bounds it: a direction
holds at most that many out-of-order bytes before committing a gap.  The
default is 256 KiB per direction.

**Reading is streaming.** The capture itself is read one packet at a time, so
a capture larger than memory is fine as long as the two limits above are.

## Interoperability

**The spec version is fixed by the `zpf` library**, not by zpfwire.  Check it
with `zpfwire --version`, which reports `zpf.SPEC_VERSION` rather than a
hard-coded number.  The format guarantees no upgrade path across a minor
version while it is below 1.0, so a file written against one minor may be
refused by a library implementing another.

**Neither sibling is on PyPI yet.**  `pyproject.toml` floors both —
`packeteer>=0.14.0`, `zpf>=0.3.0` — but with nothing to resolve against, a
floor is documentation as much as a constraint: it names the releases the
code was built against, which each `CHANGELOG.md` entry names too, and it
makes an older checkout fail at import rather than somewhere subtler.  Both
are installed editable from the checkouts beside this one, so what is
actually in use is whatever those checkouts are at.
