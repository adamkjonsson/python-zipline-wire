# Plans

Working documents: the release plans and design arguments that carried this
project between versions. They are kept because they record *why* a thing was
built the way it was — an argument that neither the code nor the commit log
states in full.

**They are historical, not normative.** A plan describes what was intended at
the time it was written, and one may describe a spec version this project no
longer writes. Where a plan disagrees with the code, the code is right; where
it disagrees with [`CLAUDE.md`](../CLAUDE.md) or [`docs/`](../docs/), those are
right. Nothing here is maintained after the work it describes has landed.

The live records stay in the project root:
[`CHANGELOG.md`](../CHANGELOG.md) for what shipped, and
[`PLAN.md`](PLAN.md) for the original design and phasing.

| Document | What it is |
| --- | --- |
| [`V0.1.0-RELEASE-PLAN.md`](V0.1.0-RELEASE-PLAN.md) | The first tagged release: the port to python-zipline `0.3.0` / spec `0.19` ([#13](https://github.com/adamkjonsson/python-zipline-wire/issues/13)), the coalesced-`ack` rule ([#11](https://github.com/adamkjonsson/python-zipline-wire/issues/11)), and the release mechanics. |
| [`V0.2.0-RELEASE-PLAN.md`](V0.2.0-RELEASE-PLAN.md) | The packeteer `0.14.0` step ([#16](https://github.com/adamkjonsson/python-zipline-wire/issues/16)) and the withdrawal of `favor-new`; records why the TCP Timestamps work ([#17](https://github.com/adamkjonsson/python-zipline-wire/issues/17)) was held for `0.3.0`, what it turned out to need, and the three upstream issues filed for it. |
| [`V0.3.0-RELEASE-PLAN.md`](V0.3.0-RELEASE-PLAN.md) | The TCP Timestamps release: the reassembler reads the option for the first time ([#17](https://github.com/adamkjonsson/python-zipline-wire/issues/17)) and `favor-acked` arrives as the second overlap policy ([#18](https://github.com/adamkjonsson/python-zipline-wire/issues/18)); records what the four real captures from packeteer `0.15.0` and `0.16.0` measured, the duplicate rule and why it uses no threshold, and the held-run design. |
| [`V0.4.0-RELEASE-PLAN.md`](V0.4.0-RELEASE-PLAN.md) | The spec `0.21` release: the port to python-zipline `0.5.0` ([#26](https://github.com/adamkjonsson/python-zipline-wire/issues/26)), the deletion of the zipline#146 shim ([#27](https://github.com/adamkjonsson/python-zipline-wire/issues/27)) and the finding it exposed on the ack axis (zipline#151), `capture-gap` as the specification's word ([#28](https://github.com/adamkjonsson/python-zipline-wire/issues/28)) and the `adjacency` field ([#29](https://github.com/adamkjonsson/python-zipline-wire/issues/29)); introduces the two release habits, the documentation sweep and filing every carry-over. |
| [`V0.5.0-RELEASE-PLAN.md`](V0.5.0-RELEASE-PLAN.md) | The `.zpf`-input release, on spec `0.23`: a `.zpf` of decoded IP packets converted to sessions on python-zipline's `sessionize_stage` ([#35](https://github.com/adamkjonsson/python-zipline-wire/issues/35)) and exported as a pcap ([#36](https://github.com/adamkjonsson/python-zipline-wire/issues/36)), the generated `favor-acked` test and the packeteer floor ([#30](https://github.com/adamkjonsson/python-zipline-wire/issues/30)), the fifth site decided ([#31](https://github.com/adamkjonsson/python-zipline-wire/issues/31)), and the hold bound left open ([#32](https://github.com/adamkjonsson/python-zipline-wire/issues/32)); developed against the python-zipline `0.6.0` release candidate and released against python-zipline `0.6.0` and packeteer `0.18.0`; records what a real kober `packets.zpf` looks like, and why `--checksum drop` became TCP-only. |
| [`V0.6.0-RELEASE-PLAN.md`](V0.6.0-RELEASE-PLAN.md) | The performance release, released against python-zipline `0.7.0` and packeteer `0.20.0`: the reassembler's three superlinear paths ([#43](https://github.com/adamkjonsson/python-zipline-wire/issues/43), [#44](https://github.com/adamkjonsson/python-zipline-wire/issues/44), [#45](https://github.com/adamkjonsson/python-zipline-wire/issues/45)) and two small costs ([#46](https://github.com/adamkjonsson/python-zipline-wire/issues/46), [#47](https://github.com/adamkjonsson/python-zipline-wire/issues/47)), each proved byte-identical to `0.5.0`; the dev venv and the sibling pins put right first ([#41](https://github.com/adamkjonsson/python-zipline-wire/issues/41), [#42](https://github.com/adamkjonsson/python-zipline-wire/issues/42)); and pure ACKs stored by default, with an opt-out that reproduces `0.5.0` exactly ([#37](https://github.com/adamkjonsson/python-zipline-wire/issues/37)), the release's one breaking change; records why storing them was the wrong question to ask as flush-or-hold, and why the cost is accepted. |
