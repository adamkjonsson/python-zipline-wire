# The CLI

After installation the `zpfwire` command is available on your PATH.  Running
`python -m zpfwire` is exactly equivalent — useful in environments where the
entry-point script is not on the PATH, or when you need to target a specific
Python interpreter.

zpfwire provides two subcommands:

| Subcommand | Input | Output | Purpose |
|------------|-------|--------|---------|
| `info` | pcap / pcapng | text report | Report the conversations a capture holds, without writing anything |
| `convert` | pcap / pcapng | `.zpf` or JSON-Lines | Reassemble the capture into a capture-sourced, transport-layer file |

They are meant to be used in that order.  `info` applies the same filters and
the same flow grouping as `convert` does, so it answers "what would I get?"
before you commit to an output file:

```
pcap  --info--→  what is in here  --convert--→  .zpf
```

The CLI is a thin wrapper.  Every option below maps onto an argument of
{func}`~zpfwire.convert.capture_to_zpf` or a field of
{class}`~zpfwire.options.ReassemblyOptions`, and anything the CLI can do is
available from Python — see {doc}`../guide/index`.

## Options shared by both subcommands

Both accept the same capture-reading and filtering options.

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

Both subcommands exit `0` on success and `1` on error, printing
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
```
