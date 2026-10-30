# Vendored specification vectors

Files copied byte for byte from the specification's own suite,
[`zipline/vectors/`](https://github.com/adamkjonsson/zipline/tree/v0.24/vectors),
so that this suite does not depend on a checkout beside it.  They are the
specification's, not this project's: never edit them, and re-vendor them
from a tag when the spec this tree writes moves.

| Directory | Tag | What it is used for |
| --- | --- | --- |
| `tunnel/` | `v0.24` (`f15bb81`) | The decrypted-tunnel chain of § *Worked example: a decrypted tunnel*: `outer.zpf → packets.zpf → inner.zpf → http.zpf`, binary and JSONL.  `packets.zpf` is real IPv4 + TCP labelled `net:ip` since `0.22`, so converting it rebuilds `inner.zpf` — the acceptance test for a `.zpf` of packets as input ([#35](https://github.com/adamkjonsson/python-zipline-wire/issues/35)). |
| `sessionized-fragments/` | `v0.24` (`f15bb81`) | A UDP datagram IP-fragmented inside a tunnel, as a `.zpf` of packets (`packets.zpf`), and the transport file a sessionizer writes from it (`inner.zpf`): one `message` record citing both fragments, which spec `0.24` permits ([zipline#166](https://github.com/adamkjonsson/zipline/issues/166), [#75](https://github.com/adamkjonsson/python-zipline-wire/issues/75)).  Its record is stamped with the first fragment's time, a vector defect ([zipline#175](https://github.com/adamkjonsson/zipline/issues/175)); the test checks everything else. |

To re-vendor:

```bash
for f in outer packets inner http; do
    git -C ../zipline show vX.Y:vectors/tunnel/$f.zpf   > tests/vectors/tunnel/$f.zpf
    git -C ../zipline show vX.Y:vectors/tunnel/$f.jsonl > tests/vectors/tunnel/$f.jsonl
done
```
