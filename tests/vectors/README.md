# Vendored specification vectors

Files copied byte for byte from the specification's own suite,
[`zipline/vectors/`](https://github.com/adamkjonsson/zipline/tree/v0.23/vectors),
so that this suite does not depend on a checkout beside it.  They are the
specification's, not this project's: never edit them, and re-vendor them
from a tag when the spec this tree writes moves.

| Directory | Tag | What it is used for |
| --- | --- | --- |
| `tunnel/` | `v0.23` (`3808439`) | The decrypted-tunnel chain of § *Worked example: a decrypted tunnel*: `outer.zpf → packets.zpf → inner.zpf → http.zpf`, binary and JSONL.  `packets.zpf` is real IPv4 + TCP labelled `net:ip` since `0.22`, so converting it rebuilds `inner.zpf` — the acceptance test for a `.zpf` of packets as input ([#35](https://github.com/adamkjonsson/python-zipline-wire/issues/35)). |

To re-vendor:

```bash
for f in outer packets inner http; do
    git -C ../zipline show vX.Y:vectors/tunnel/$f.zpf   > tests/vectors/tunnel/$f.zpf
    git -C ../zipline show vX.Y:vectors/tunnel/$f.jsonl > tests/vectors/tunnel/$f.jsonl
done
```
