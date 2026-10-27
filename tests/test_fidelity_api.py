"""The public ``zpfwire.fidelity`` and ``zpfwire fidelity`` (``0.8.0``, #63).

The scorer under them is tested in ``test_fidelity.py``.  These test what
the promotion added: evaluating a policy over seeds, the report a user reads,
the command line, and that an ordinary ``import zpfwire`` pays nothing for
any of it.
"""

from __future__ import annotations

import dataclasses
import json
import pathlib
import subprocess
import sys

import pytest

from zpfwire import ReassemblyOptions, fidelity
from zpfwire.__main__ import main
from zpfwire.fidelity import Impairments, Scenario, Unclean, evaluate, parse_shape

CORRUPTION = Scenario(impairments=Impairments(payload_corruption_probability=0.2))
"""The prototype's corruption row, which ``favor-old`` keeps and ``favor-acked`` swaps out."""


def cli(monkeypatch: pytest.MonkeyPatch, *argv: str) -> None:
    monkeypatch.setattr(sys, "argv", ["zpfwire", *argv])
    main()


def test_import_zpfwire_does_not_load_the_generators():
    """``zpfwire.fidelity`` imports packeteer's generators; a conversion never needs them."""
    code = "import sys, zpfwire; print('zpfwire.fidelity' in sys.modules)"
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                         check=True)
    assert out.stdout.strip() == "False"


@pytest.mark.parametrize(("text", "shape"), [
    ("c2s:3000,s2c:9000", (("c2s", 3000), ("s2c", 9000))),
    (" s2c:1 , c2s:2 ", (("s2c", 1), ("c2s", 2))),
])
def test_a_shape_parses(text: str, shape: tuple[tuple[str, int], ...]):
    assert parse_shape(text) == shape


@pytest.mark.parametrize("text", ["", "c2s", "up:10", "c2s:0", "c2s:-1", "c2s:1,"])
def test_a_malformed_shape_is_refused(text: str):
    with pytest.raises(ValueError, match="c2s:LENGTH or s2c:LENGTH"):
        parse_shape(text)


def test_an_evaluation_tells_two_policies_apart():
    """The prototype's corruption row: what ``0.7.0`` found, through the public API."""
    old = evaluate(CORRUPTION, seeds=range(10))
    acked = evaluate(CORRUPTION, ReassemblyOptions(overlap="favor-acked"), seeds=range(10))

    assert min(m.total.fidelity for m in old.scored) < 1
    assert all(m.total.fidelity == 1 for m in acked.scored)
    assert len(old.scored) == len(acked.scored) == 10
    assert "| fidelity: correct ÷ sent | 1 | 1 |" in acked.report()


def test_an_evaluation_reproduces_byte_for_byte():
    first = evaluate(CORRUPTION, seeds=range(3))
    again = evaluate(CORRUPTION, seeds=range(3))
    assert first.report() == again.report()
    assert list(first.jsonl()) == list(again.jsonl())


def test_the_report_names_the_scenario_and_the_policy():
    scenario = Scenario(shape=parse_shape("c2s:100,s2c:200"),
                        impairments=Impairments(packet_loss_probability=0.1))
    report = evaluate(scenario, ReassemblyOptions(overlap="favor-acked", acked_hold=10.0),
                      seeds=range(2, 5), sequenced=True).report()

    assert "- messages: c2s 100, s2c 200 (100 bytes c2s, 200 s2c)" in report
    assert "- impairments: packet_loss_probability 0.1" in report
    assert "- seeds: 2–4 (3)" in report
    assert "- overlap favor-acked, acked_hold 10.0, sequenced" in report
    assert evaluate(scenario, seeds=range(1)).report().count("- zpfwire's defaults") == 1


def test_one_json_line_per_seed():
    lines = [json.loads(line) for line in evaluate(CORRUPTION, seeds=range(4)).jsonl()]

    assert [line["seed"] for line in lines] == [0, 1, 2, 3]
    assert all(set(line["bytes"]) == {"c2s", "s2c"} for line in lines)
    assert all("CORRUPT" in line["realised"] for line in lines if line["realised"])


def test_an_unclean_file_is_reported_as_a_bug_not_raised(monkeypatch: pytest.MonkeyPatch):
    def unclean(*_: object, **__: object) -> None:
        raise Unclean("diagnostics ['made up']")

    monkeypatch.setattr("zpfwire.fidelity._evaluate.measure", unclean)
    e = evaluate(Scenario(), seeds=range(2))

    assert e.unclean == 2 and e.scored == []
    assert "**2 read back unclean, which is a bug**" in e.report()


def test_a_void_run_is_reported_and_not_scored(monkeypatch: pytest.MonkeyPatch):
    real = fidelity._evaluate.run

    def voided(scenario: Scenario) -> fidelity.Run:
        return dataclasses.replace(real(scenario), void=("made up",))

    monkeypatch.setattr("zpfwire.fidelity._evaluate.run", voided)
    e = evaluate(Scenario(), seeds=range(1))

    assert e.scored == []
    assert "0 of 1 runs scored; 1 void" in e.report()
    assert "| 0 | – | *void* |" in e.report()


def test_the_cli_prints_the_report_and_writes_the_lines(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
):
    lines = tmp_path / "runs.jsonl"
    cli(monkeypatch, "fidelity", "--payload-corruption", "0.2", "--overlap", "favor-acked",
        "--seeds", "3", "--first-seed", "1", "--jsonl", str(lines))

    expected = evaluate(CORRUPTION, ReassemblyOptions(overlap="favor-acked"),
                        seeds=range(1, 4))
    assert capsys.readouterr().out == expected.report()
    assert lines.read_text().splitlines() == list(expected.jsonl())


def test_the_cli_takes_packeteer_s_names_for_the_network(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
):
    cli(monkeypatch, "fidelity", "--seeds", "1", "--messages", "c2s:500,s2c:700",
        "--psh-probability", "1", "--packet-loss", "0.1", "--retransmit-lost",
        "--retransmission-probability", "0.1", "--retransmission-timeout", "0.5",
        "--duplicate", "0.1", "--server-rst", "0.5", "--rst-propagation-delay", "0.01",
        "--stray-packets", "1", "--stray-timing-window", "3", "--stray-timestamps")

    out = capsys.readouterr().out
    assert "- psh_probability: 1.0" in out
    for name in ("packet_loss_probability 0.1", "retransmit_lost True",
                 "retransmission_probability 0.1", "retransmission_timeout 0.5",
                 "duplicate_probability 0.1", "server_rst_probability 0.5",
                 "rst_propagation_delay 0.01", "stray_packet_count 1",
                 "stray_timing_window 3", "stray_timestamps True"):
        assert name in out


def test_the_cli_exits_1_on_an_unclean_file(monkeypatch: pytest.MonkeyPatch):
    def unclean(*_: object, **__: object) -> None:
        raise Unclean("diagnostics ['made up']")

    monkeypatch.setattr("zpfwire.fidelity._evaluate.measure", unclean)
    with pytest.raises(SystemExit) as exit_:
        cli(monkeypatch, "fidelity", "--seeds", "1")
    assert exit_.value.code == 1


@pytest.mark.parametrize(("argv", "message"), [
    (["--packet-loss", "1.5"], "not a probability"),
    (["--messages", "c2s:0"], "positive length"),
])
def test_the_cli_refuses_a_malformed_scenario(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
    argv: list[str], message: str,
):
    with pytest.raises(SystemExit):
        cli(monkeypatch, "fidelity", *argv)
    assert message in capsys.readouterr().err
