# The CLI

After installation the `zpfwire` command is available on your PATH.  Running
`python -m zpfwire` is exactly equivalent — useful in environments where the
entry-point script is not on the PATH, or when you need to target a specific
Python interpreter.

zpfwire provides four subcommands:

| Subcommand | Input | Output | Purpose |
|------------|-------|--------|---------|
| `info` | pcap / pcapng | text report | Report the conversations a capture holds, without writing anything |
| `convert` | pcap / pcapng, or a `.zpf` of packets | `.zpf` or JSON-Lines | Reassemble the input into a transport-layer file |
| `pcap` | a `.zpf` of packets | pcap | Export the packets, for Wireshark |
| `fidelity` | a scenario, as flags | Markdown report | Measure a reassembly policy against TCP traffic packeteer generates |

The first two are meant to be used in that order.  `info` applies the same filters and
the same flow grouping as `convert` does, so it answers "what would I get?"
before you commit to an output file:

```
pcap  --info--→  what is in here  --convert--→  .zpf
```

The CLI is a thin wrapper.  Every option below maps onto an argument of
{func}`~zpfwire.convert.capture_to_zpf`,
{func}`~zpfwire.packets.packets_to_zpf` or
{func}`~zpfwire.packets.packets_to_pcap` or
{func}`~zpfwire.fidelity.evaluate`, or a field of
{class}`~zpfwire.options.ReassemblyOptions`, and anything the CLI can do is
available from Python — see {doc}`../guide/index`.

## Options shared by the subcommands

`info`, `convert` and `pcap` take the input as their positional argument and
accept the filtering options below; `--link-type` too, and `--tick-hz` for a
capture.  `fidelity` reads no input: it generates its own.

### Reading

| Flag | What it does |
|------|--------------|
| `--link-type N` | Override the link type, for input whose header does not state one |
| `--tick-hz N` | Override the tick rate taken from the capture header |

`--tick-hz` is rarely needed: the resolution is read from the file, including
the pcapng `if_tsresol` option, and each packet is rescaled into the file-level
rate.  Reach for it when a capture declares a resolution you know to be wrong.

### Filtering

Values are comma-separated, a `!` prefix negates, and addresses accept CIDR.
See {doc}`../guide/filtering` for the semantics, which come from packeteer's
own `PacketFilter`.

| Flag | Keeps |
|------|-------|
| `--proto` | Only this transport (`tcp`, `udp`) |
| `--port` | Packets using these ports in either direction |
| `--src-port` / `--dst-port` | These source / destination ports |
| `--src` / `--dst` | These source / destination addresses |
| `--host` | These addresses at either end |

## Exit status

Every subcommand exits `0` on success and `1` on error, printing
`Error: <message>` to stderr.  A conversion that loses bytes is **not** an
error — it exits `0` and says so in the summary, because losing bytes is a
documented outcome of the reassembly policy rather than a failure.

A conversion that could produce *nothing* is: `convert` refuses a capture
whose link type packeteer cannot decode, exactly as it refuses
`--no-tcp --no-udp`, rather than write a valid, empty file.  `info` reports
the same fact and continues.

```{toctree}
:maxdepth: 1

info
convert
pcap
fidelity
```
