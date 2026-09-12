"""zpfwire — turn network captures into Zipline Payload Format files.

Commands:
  convert   write a .zpf (or its JSON-Lines projection) from a capture
  info      list the conversations a capture holds, without writing anything

Examples:
  # Convert a capture, TCP reassembly included
  zpfwire convert capture.pcap -o capture.zpf

  # Look before converting
  zpfwire info capture.pcap

  # Only HTTPS traffic from one subnet
  zpfwire convert capture.pcap -o https.zpf --dst-port 443 --src 10.0.0.0/24

  # Emit the readable JSON-Lines projection instead of the binary container
  zpfwire convert capture.pcap -o capture.jsonl --jsonl

  # Never wait for out-of-order segments; commit every gap immediately
  zpfwire convert capture.pcap -o strict.zpf --reorder-window 0

  # Discard corrupt segments the way a receiver does, keeping the retransmission
  zpfwire convert lossy.pcap -o lossy.zpf --checksum drop

"""

from __future__ import annotations

import argparse
import sys
from importlib.metadata import PackageNotFoundError, version

import zpf
from packeteer.filter import PacketFilter

from zpfwire.capture import CaptureReader
from zpfwire.convert import convert, describe_source
from zpfwire.filter import matcher
from zpfwire.options import CHECKSUM_POLICIES, OVERLAP_POLICIES, ReassemblyOptions
from zpfwire.survey import survey

_ERRORS = (OSError, ValueError, zpf.ZpfError)


def _version() -> str:
    try:
        return version("zpfwire")
    except PackageNotFoundError:
        return "unknown"


def _positive_int(value: str) -> int:
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError(f"{value} must not be negative")
    return number


def _positive_float(value: str) -> float:
    number = float(value)
    if number < 0:
        raise argparse.ArgumentTypeError(f"{value} must not be negative")
    return number


def _build_packet_filter(args: argparse.Namespace) -> PacketFilter | None:
    """Assemble a filter from the CLI flags, or ``None`` if none were given."""
    def split(value: str | None) -> list[str]:
        return [part for part in (value or "").split(",") if part]

    packet_filter = PacketFilter(
        proto=args.proto,
        port=split(args.port),
        src_port=split(args.src_port),
        dst_port=split(args.dst_port),
        src=split(args.src),
        dst=split(args.dst),
        host=split(args.host),
    )
    return None if packet_filter.is_empty() else packet_filter


def _options(args: argparse.Namespace) -> ReassemblyOptions:
    return ReassemblyOptions(
        overlap=args.overlap,
        reorder_window=args.reorder_window,
        flush_timeout=args.flush_timeout,
        session_timeout=args.session_timeout,
        coalesce=not args.no_coalesce,
        checksum=args.checksum,
    )


# ── convert subcommand ──────────────────────────────────────────────────


def _undecodable(reader: CaptureReader) -> str:
    """Say, in one sentence shared by both commands, that packeteer cannot read the link type."""
    return (f"link type {reader.link_type} is one packeteer cannot decode, "
            f"so every packet in the capture is skipped")


def _cmd_convert(args: argparse.Namespace) -> None:
    reader = CaptureReader(path=args.capture, link_type=args.link_type, tick_hz=args.tick_hz)
    # A file that would be valid and empty is not a conversion, any more than
    # one with both transports switched off; the API will still write it.
    if not reader.link_type_supported:
        raise ValueError(f"{_undecodable(reader)}: nothing to convert")
    digest, uri = describe_source(args.capture)
    wanted = {name for name, on in (("tcp", not args.no_tcp), ("udp", not args.no_udp)) if on}
    if not wanted:
        raise ValueError("--no-tcp and --no-udp leave nothing to convert")

    stats = convert(
        reader,
        args.output,
        options=_options(args),
        wanted=wanted,
        digest=digest,
        uri=uri,
        packet_filter=matcher(_build_packet_filter(args)),
        face="jsonl" if args.jsonl else "binary",
        sequenced=args.sequenced,
    )

    if not args.quiet:
        print(stats.summary())
        if not stats.lossless:
            sys.stdout.flush()
            print(
                "Note: some bytes never reached the output. "
                "Raise --reorder-window or --flush-timeout to wait longer.",
                file=sys.stderr,
            )


# ── info subcommand ─────────────────────────────────────────────────────


def _cmd_info(args: argparse.Namespace) -> None:
    reader = CaptureReader(path=args.capture, link_type=args.link_type, tick_hz=args.tick_hz)
    flows = survey(reader, packet_filter=matcher(_build_packet_filter(args)))

    print(f"{args.capture}: {reader.packet_count} packets, tick_hz {reader.tick_hz}")
    if not reader.link_type_supported:
        print(_undecodable(reader))
    print(f"{len(flows)} conversation(s) would become sessions\n")
    print(f"{'proto':<6} {'packets':>8} {'payload':>10} {'seconds':>8}  flow")
    for flow in sorted(flows, key=lambda f: -f.payload_bytes):
        print(
            f"{flow.key.protocol:<6} {flow.packets:>8} {flow.payload_bytes:>10} "
            f"{flow.duration(reader.tick_hz):>8.3f}  {flow.key.text}",
        )
    for reason, count in sorted(reader.skipped.items()):
        print(f"\nskipped {count} ({reason})")


# ── entry point ─────────────────────────────────────────────────────────


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("capture", help="pcap or pcapng file to read")
    parser.add_argument("--link-type", type=int, default=None,
                        help="override the capture's link type")
    parser.add_argument("--tick-hz", type=_positive_int, default=None,
                        help="override the tick rate derived from the capture header")

    group = parser.add_argument_group(
        "filtering",
        "Comma-separated; prefix a value with '!' to negate. Addresses accept CIDR.",
    )
    group.add_argument("--proto", default=None, help="keep only this transport (tcp, udp)")
    group.add_argument("--port", default=None, help="keep packets using these ports either way")
    group.add_argument("--src-port", default=None, help="keep these source ports")
    group.add_argument("--dst-port", default=None, help="keep these destination ports")
    group.add_argument("--src", default=None, help="keep these source addresses")
    group.add_argument("--dst", default=None, help="keep these destination addresses")
    group.add_argument("--host", default=None, help="keep these addresses on either end")


def main() -> None:
    """Run the command line interface."""
    parser = argparse.ArgumentParser(
        prog="zpfwire",
        description="Turn network captures into Zipline Payload Format (.zpf) files.",
        epilog=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version",
                        version=f"zpfwire {_version()} (zipline "
                                f"{zpf.SPEC_VERSION[0]}.{zpf.SPEC_VERSION[1]})")
    subparsers = parser.add_subparsers(dest="command", required=True)

    convert_parser = subparsers.add_parser(
        "convert", help="write a .zpf from a capture",
        description="Convert a capture into a capture-sourced, transport-layer .zpf file.",
    )
    _add_common(convert_parser)
    convert_parser.add_argument("-o", "--output", required=True, help="file to write")
    convert_parser.add_argument("--jsonl", action="store_true",
                                help="write the JSON-Lines projection instead of the container")
    convert_parser.add_argument("--no-tcp", action="store_true", help="skip TCP conversations")
    convert_parser.add_argument("--no-udp", action="store_true", help="skip UDP conversations")
    convert_parser.add_argument(
        "--sequenced", action="store_true",
        help="store TCP sessions in causal order and mark them SEQUENCED "
             "(buffers each session until it ends)",
    )
    convert_parser.add_argument("-q", "--quiet", action="store_true",
                                help="do not print the summary")

    reassembly = convert_parser.add_argument_group(
        "reassembly",
        "These decide which bytes reach the output: once a record is written past "
        "missing bytes, those bytes may never be written. The settings are hashed "
        "into the file's decoder descriptor so a conversion can be reproduced.",
    )
    reassembly.add_argument("--overlap", choices=OVERLAP_POLICIES, default="favor-old",
                            help="which copy wins when retransmitted bytes disagree")
    reassembly.add_argument("--reorder-window", type=_positive_int, default=262_144,
                            metavar="BYTES",
                            help="bytes held out of order before a gap is committed")
    reassembly.add_argument("--flush-timeout", type=_positive_float, default=5.0,
                            metavar="SECONDS",
                            help="how long a gap may stay unfilled before it is committed")
    reassembly.add_argument("--session-timeout", type=_positive_float, default=300.0,
                            metavar="SECONDS",
                            help="silence after which a conversation is closed")
    reassembly.add_argument("--no-coalesce", action="store_true",
                            help="emit one record per segment instead of per byte run")
    reassembly.add_argument("--checksum", choices=CHECKSUM_POLICIES, default="ignore",
                            help="what to do with a packet whose transport checksum "
                                 "does not verify (default: ignore)")
    convert_parser.set_defaults(func=_cmd_convert)

    info_parser = subparsers.add_parser(
        "info", help="list the conversations a capture holds",
        description="Report what a conversion would produce, without writing anything.",
    )
    _add_common(info_parser)
    info_parser.set_defaults(func=_cmd_info)

    args = parser.parse_args()
    try:
        args.func(args)
    except _ERRORS as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
