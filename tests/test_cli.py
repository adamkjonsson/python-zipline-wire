from __future__ import annotations

import pathlib

import pytest
import zpf
from helpers import CAPTURES

from zpfwire.__main__ import main


def run(monkeypatch: pytest.MonkeyPatch, *argv: str) -> None:
    """Invoke the CLI as if from the shell."""
    monkeypatch.setattr("sys.argv", ["zpfwire", *argv])
    main()


def clean(path: pathlib.Path) -> list[object]:
    with zpf.open(path) as reader:
        for session in reader.sessions():
            list(session.records())
        return list(reader.diagnostics)


# ── convert ─────────────────────────────────────────────────────────────


def test_convert_writes_a_valid_file(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
                                     capsys: pytest.CaptureFixture[str]):
    out = tmp_path / "out.zpf"
    run(monkeypatch, "convert", str(CAPTURES / "no_errors.pcap"), "-o", str(out))

    assert out.exists()
    assert clean(out) == []
    assert "sessions" in capsys.readouterr().out


def test_convert_is_quiet_on_request(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
                                     capsys: pytest.CaptureFixture[str]):
    out = tmp_path / "out.zpf"
    run(monkeypatch, "convert", str(CAPTURES / "no_errors.pcap"), "-o", str(out), "-q")

    assert capsys.readouterr().out == ""


def test_convert_warns_when_bytes_were_lost(tmp_path: pathlib.Path,
                                            monkeypatch: pytest.MonkeyPatch,
                                            capsys: pytest.CaptureFixture[str]):
    out = tmp_path / "out.zpf"
    run(monkeypatch, "convert", str(CAPTURES / "packet_loss.pcap"), "-o", str(out))

    captured = capsys.readouterr()
    assert "gaps" in captured.out
    assert "never reached the output" in captured.err


def test_convert_can_write_the_jsonl_face(tmp_path: pathlib.Path,
                                          monkeypatch: pytest.MonkeyPatch):
    out = tmp_path / "out.jsonl"
    run(monkeypatch, "convert", str(CAPTURES / "udp.pcap"), "-o", str(out), "--jsonl", "-q")

    assert out.read_text().startswith('{"type":"file"')
    assert clean(out) == []


def test_convert_honours_the_transport_switches(tmp_path: pathlib.Path,
                                                monkeypatch: pytest.MonkeyPatch):
    out = tmp_path / "out.zpf"
    run(monkeypatch, "convert", str(CAPTURES / "udp.pcap"), "-o", str(out), "--no-udp", "-q")

    with zpf.open(out) as reader:
        assert list(reader.sessions()) == []


def test_convert_refuses_to_skip_everything(tmp_path: pathlib.Path,
                                            monkeypatch: pytest.MonkeyPatch,
                                            capsys: pytest.CaptureFixture[str]):
    out = tmp_path / "out.zpf"
    with pytest.raises(SystemExit) as exit_info:
        run(monkeypatch, "convert", str(CAPTURES / "udp.pcap"), "-o", str(out),
            "--no-tcp", "--no-udp")

    assert exit_info.value.code == 1
    assert "nothing to convert" in capsys.readouterr().err


def test_reassembly_flags_reach_the_reassembler(tmp_path: pathlib.Path,
                                                monkeypatch: pytest.MonkeyPatch):
    """--no-coalesce should produce strictly more records than the default."""
    default = tmp_path / "default.zpf"
    split = tmp_path / "split.zpf"
    capture = str(CAPTURES / "no_errors.pcap")

    run(monkeypatch, "convert", capture, "-o", str(default), "-q")
    run(monkeypatch, "convert", capture, "-o", str(split), "--no-coalesce", "-q")

    def count(path: pathlib.Path) -> int:
        with zpf.open(path) as reader:
            return sum(len(list(s.records())) for s in reader.sessions())

    assert count(split) > count(default)


def test_the_policy_is_recorded_in_the_file(tmp_path: pathlib.Path,
                                            monkeypatch: pytest.MonkeyPatch):
    out = tmp_path / "out.zpf"
    run(monkeypatch, "convert", str(CAPTURES / "no_errors.pcap"), "-o", str(out),
        "--reorder-window", "1024", "--overlap", "favor-new", "-q")

    from zpfwire import ReassemblyOptions

    expected = ReassemblyOptions(reorder_window=1024, overlap="favor-new").params_digest()
    with zpf.open(out) as reader:
        assert next(iter(reader.decoders.values())).params_digest == expected


# ── filtering ───────────────────────────────────────────────────────────


def test_filtering_by_port_selects_conversations(tmp_path: pathlib.Path,
                                                 monkeypatch: pytest.MonkeyPatch):
    out = tmp_path / "out.zpf"
    run(monkeypatch, "convert", str(CAPTURES / "http_example.pcapng"), "-o", str(out),
        "--dst-port", "80", "-q")

    with zpf.open(out) as reader:
        keys = [s.key for s in reader.sessions()]
    assert keys
    assert all(":80" in key for key in keys)


def test_a_filter_that_matches_nothing_yields_no_sessions(tmp_path: pathlib.Path,
                                                          monkeypatch: pytest.MonkeyPatch):
    out = tmp_path / "out.zpf"
    run(monkeypatch, "convert", str(CAPTURES / "no_errors.pcap"), "-o", str(out),
        "--host", "203.0.113.9", "-q")

    with zpf.open(out) as reader:
        assert list(reader.sessions()) == []


def test_filtering_accepts_cidr_and_negation(tmp_path: pathlib.Path,
                                             monkeypatch: pytest.MonkeyPatch):
    out = tmp_path / "out.zpf"
    run(monkeypatch, "convert", str(CAPTURES / "no_errors.pcap"), "-o", str(out),
        "--src", "10.0.0.0/24", "-q")

    with zpf.open(out) as reader:
        assert list(reader.sessions())

    run(monkeypatch, "convert", str(CAPTURES / "no_errors.pcap"), "-o", str(out),
        "--src", "!10.0.0.0/24", "-q")

    with zpf.open(out) as reader:
        assert list(reader.sessions()) == []


def test_an_invalid_filter_value_is_reported(tmp_path: pathlib.Path,
                                             monkeypatch: pytest.MonkeyPatch,
                                             capsys: pytest.CaptureFixture[str]):
    out = tmp_path / "out.zpf"
    with pytest.raises(SystemExit) as exit_info:
        run(monkeypatch, "convert", str(CAPTURES / "no_errors.pcap"), "-o", str(out),
            "--src-port", "notaport")

    assert exit_info.value.code == 1
    assert "Error:" in capsys.readouterr().err


# ── info ────────────────────────────────────────────────────────────────


def test_info_lists_conversations_without_writing(monkeypatch: pytest.MonkeyPatch,
                                                  capsys: pytest.CaptureFixture[str]):
    run(monkeypatch, "info", str(CAPTURES / "http_example.pcapng"))

    out = capsys.readouterr().out
    assert "conversation(s) would become sessions" in out
    assert "tcp" in out
    assert "146.190.62.39:80" in out


def test_info_reports_what_it_skipped(monkeypatch: pytest.MonkeyPatch,
                                      capsys: pytest.CaptureFixture[str]):
    run(monkeypatch, "info", str(CAPTURES / "sctp.pcap"))

    out = capsys.readouterr().out
    assert "not-tcp-or-udp" in out


def test_info_respects_filters(monkeypatch: pytest.MonkeyPatch,
                               capsys: pytest.CaptureFixture[str]):
    run(monkeypatch, "info", str(CAPTURES / "http_example.pcapng"))
    unfiltered = capsys.readouterr().out

    run(monkeypatch, "info", str(CAPTURES / "http_example.pcapng"), "--port", "64774")
    filtered = capsys.readouterr().out

    assert "4 conversation(s)" in unfiltered
    assert "1 conversation(s)" in filtered
    assert "64774" in filtered
    assert "64778" not in filtered


# ── plumbing ────────────────────────────────────────────────────────────


def test_a_missing_capture_exits_with_an_error(tmp_path: pathlib.Path,
                                               monkeypatch: pytest.MonkeyPatch,
                                               capsys: pytest.CaptureFixture[str]):
    with pytest.raises(SystemExit) as exit_info:
        run(monkeypatch, "convert", str(tmp_path / "nope.pcap"), "-o", str(tmp_path / "o.zpf"))

    assert exit_info.value.code == 1
    assert "Error:" in capsys.readouterr().err


def test_version_reports_both_tool_and_spec(monkeypatch: pytest.MonkeyPatch,
                                            capsys: pytest.CaptureFixture[str]):
    with pytest.raises(SystemExit) as exit_info:
        run(monkeypatch, "--version")

    assert exit_info.value.code == 0
    out = capsys.readouterr().out
    assert "zpfwire" in out
    assert "zipline 0.16" in out


def test_a_command_is_required(monkeypatch: pytest.MonkeyPatch):
    with pytest.raises(SystemExit) as exit_info:
        run(monkeypatch)

    assert exit_info.value.code == 2


def test_negative_numeric_flags_are_rejected(tmp_path: pathlib.Path,
                                             monkeypatch: pytest.MonkeyPatch):
    with pytest.raises(SystemExit) as exit_info:
        run(monkeypatch, "convert", str(CAPTURES / "udp.pcap"),
            "-o", str(tmp_path / "o.zpf"), "--reorder-window", "-1")

    assert exit_info.value.code == 2
