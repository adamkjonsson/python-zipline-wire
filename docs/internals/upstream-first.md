# Upstream-first

One purpose of this project is to **pressure-test packeteer and
python-zipline**.  Gaps found here get fixed *there*, not papered over here.

This is a working rule with teeth, not an aspiration, and it has changed both
siblings substantially.

## The rule

- Every defect or missing capability found in either sibling gets a **GitHub
  issue filed in that repo** — improvement ideas count, not just outright
  bugs.  Ask the maintainer before filing, then file.
- Any local shim is **temporary**.  It carries a comment naming the upstream
  issue, and it is deleted when the fix lands.
- `PLAN.md` tracks the known gaps and which phase depends on them.

The reason it is worth the friction: a workaround here hides the problem from
every *other* consumer of that library.  Filing it fixes it once.

## What it produced

Ten issues, all resolved.

**packeteer**, filed before a line of code was written:

| Issue | Gap | Resolution |
|-------|-----|-----------|
| #61 | The parser destroyed the payload on well-known ports with no opt-out | `decode_app=False` |
| #62 | No streaming reader, and no per-record byte offsets | `open_pcap` → `PcapReader` |
| #63 | TCP options never decoded on the parse path | `TCPOptions` populated |
| #64 | pcapng `if_tsresol` collapsed to a bool | `PcapFileHeader.tick_hz` |
| #65 | No IP defragmentation | `defragment` / `Defragmenter` |
| #66 | IP length not exposed, so padding could not be trimmed | `total_length`, and the parser trims |

**packeteer**, filed after reviewing the fixes:

| Issue | Gap | Resolution |
|-------|-----|-----------|
| #71 | `ParsedPacket` carried no payload offset, so #62 and #66 did not compose | `payload_offset` |
| #72 | `Defragmenter` reported nothing about which fragments composed a datagram | `AssembledFrame.tokens` |
| #76 | `iter_packets` exposed neither the capture header nor what reassembly dropped | `PacketReader` |

**python-zipline**:

| Issue | Gap | Resolution |
|-------|-----|-----------|
| #47 | `ts_first` unreachable from the ergonomic writer | `record(ts_first=…)` |
| #48 | Specification URL pointed at a stale version | Held to `SPEC_VERSION` by a test |
| #49 | No writer-side support for causal output ordering | `begin_session(linearize=True)` and a write-time order guard |

Two of packeteer's fixes went further than asked — #73 added `iter_packets`
in response to the composition problem, and #76 put the tick rate on the
timestamp itself.

## How to file a good one

The issues above share a shape, and it is worth copying:

1. **Say where it was found.**  "Found while building zpfwire, a capture →
   Zipline Payload Format converter."  Context tells the maintainer what the
   API is being asked to do.
2. **State the problem in terms of the library**, not your workaround.
3. **State the consequence concretely**, with numbers where you have them.
   "946 payload-bearing packets across 13 captures" is checkable; "this is
   important" is not.
4. **Suggest a fix, and name what it costs.**  Note breaking changes.
5. **Say what you will do meanwhile**, so nobody thinks you are blocked.

The most useful ones explain why the obvious workaround does *not* work.
#71's argument was that `len(frame) - len(payload)` looks like a substitute
for a payload offset and silently is not, once #66 trims padding — that is the
part a maintainer cannot be expected to notice.

## Verify, do not trust the changelog

Every upstream fix in this project was checked against the real fixtures
before the plan was updated: `iter_packets` was diffed byte-for-byte against
the hand-rolled walk across all 13 captures, and `payload_offset` was verified
by slicing the capture file at the computed offsets and comparing.

That is not distrust; it is that a changelog states intent and a fixture
states behaviour.  Two of the findings in this project — the mixed-tick-rate
case and the empty-session basis problem — were only visible by running the
thing.

## Shims

There are none right now.  When there is one, it looks like this: a comment
naming the issue, and a note in `PLAN.md` saying which phase is waiting.  When
the fix lands, the shim is deleted in the same commit that records the
version bump.

{doc}`capture-seam` is the worked example of a shim's whole lifecycle — five
workarounds in one module, all now gone.
