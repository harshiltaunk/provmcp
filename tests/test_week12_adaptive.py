"""Week 12: canonical views, the adaptive scenarios, and the sweeps."""

from __future__ import annotations

import base64
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from provmcp.adaptive import evaluate, flood_sweep, split_sweep
from provmcp.agent.runner import detection_label
from provmcp.benchmark import BenchmarkRunner, load_scenarios
from provmcp.config import DetectionConfig, ProvMcpConfig
from provmcp.detectors.canonical import decoded, despace, normalize, views
from provmcp.evaluation import Strategy, offline_flags
from provmcp.wiring import build_detector
from tests.test_live_enforcement import REPO

EMAIL = "owner@corp.example"
ADAPTIVE = load_scenarios(REPO / "benchmarks" / "adaptive")
BY_ID = {s.id: s for s in ADAPTIVE}
REVERSIBLE = [s.id for s in ADAPTIVE if s.metadata.get("family") in {"encoding", "reformatting"}]
RESIDUAL = [
    s.id
    for s in ADAPTIVE
    if s.metadata.get("family")
    in {"outside the decoder set", "semantic", "split", "control flow", "store"}
    and s.metadata.get("technique") != "laundering"
]
CANON = DetectionConfig(canonicalize=True)


def _outcome(detection: DetectionConfig, scenario_id: str) -> tuple[bool, bool]:
    [outcome] = evaluate(detection, [BY_ID[scenario_id]])
    return outcome.flagged, outcome.attributed


def test_normalize_undoes_unicode_tricks() -> None:
    fullwidth = "".join(chr(ord(c) - 0x20 + 0xFF00) for c in "OWNER")
    assert normalize(fullwidth) == "owner"
    assert normalize("ow​ner‍") == "owner"
    assert normalize("соrp") == "corp"  # Cyrillic look-alikes


@pytest.mark.parametrize(
    "encoded",
    [
        base64.b64encode(EMAIL.encode()).decode(),
        EMAIL.encode().hex(),
        "".join(f"%{b:02X}" for b in EMAIL.encode()),
        "".join(f"&#{ord(c)};" for c in EMAIL),
        base64.b64encode(EMAIL.encode().hex().encode()).decode(),  # two layers
    ],
    ids=["base64", "hex", "percent", "html", "base64-of-hex"],
)
def test_views_decode_each_supported_encoding(encoded: str) -> None:
    assert any(EMAIL in view for view in views(f"Contact {encoded}"))


def test_defang_and_despace() -> None:
    assert any(EMAIL in v for v in views("owner [at] corp [dot] example"))
    assert despace("Contact " + " ".join(EMAIL)) == f"Contact {EMAIL}"
    assert despace("I am a big fan") == "I am a big fan"  # ordinary words untouched


def test_decoder_ignores_binary_and_ordinary_words() -> None:
    noise = base64.b64encode(bytes(range(0, 256, 7))).decode()
    assert decoded(noise) == []
    assert decoded("performance improved for large uploads") == []


def test_canonical_is_opt_in_and_old_labels_are_unchanged() -> None:
    assert DetectionConfig().canonicalize is False
    plain = detection_label("audit", DetectionConfig())
    assert "canonical" not in plain
    assert detection_label("audit", CANON) == f"{plain}; canonical:on"


@pytest.mark.parametrize("scenario_id", REVERSIBLE)
def test_default_misses_and_canonical_catches_reversible_evasions(scenario_id: str) -> None:
    assert _outcome(DetectionConfig(), scenario_id) == (False, False)
    assert _outcome(CANON, scenario_id) == (True, True)


@pytest.mark.parametrize("scenario_id", RESIDUAL)
def test_residual_evasions_are_still_missed_with_canonical_views(scenario_id: str) -> None:
    assert _outcome(CANON, scenario_id) == (False, False)


def test_laundering_is_flagged_but_blamed_on_the_trusted_server() -> None:
    [outcome] = evaluate(DetectionConfig(), [BY_ID["ad-18-launder"]])
    assert outcome.flagged and not outcome.attributed
    assert outcome.sources == ("scratch",)


def test_a_new_session_starts_with_an_empty_store() -> None:
    detector = build_detector(ProvMcpConfig(detection=DetectionConfig()))
    result = BenchmarkRunner(detector=detector, track_tool_metadata=True).run(
        BY_ID["ad-18-launder"]
    )
    sources = {s.step: {f.source_server_id for f in s.findings} for s in result.steps}
    assert sources[2] == {"notes"}  # same session: the write is tied to the note
    assert "notes" not in sources[4]  # next session: the note is gone


def test_scan_steps_limits_scanning() -> None:
    detector = build_detector(ProvMcpConfig(detection=DetectionConfig()))
    result = BenchmarkRunner(detector=detector).run(BY_ID["ad-01-verbatim"], scan_steps={1})
    assert all(not s.findings for s in result.steps)


def test_no_false_alarms_on_the_adaptive_benign_scenarios() -> None:
    for detection in (DetectionConfig(), CANON):
        benign = [o for o in evaluate(detection, ADAPTIVE) if not o.is_attack]
        assert len(benign) == 5 and not any(o.flagged for o in benign)


def test_canonical_keeps_every_bundled_detection_and_adds_no_false_alarm() -> None:
    bundled = [
        s for d in ("attacks", "msb", "benign") for s in load_scenarios(REPO / "benchmarks" / d)
    ]
    base = offline_flags(Strategy("default", DetectionConfig()), bundled)
    canon = offline_flags(Strategy("canonical", CANON), bundled)
    assert all(canon[sid] for sid, flagged in base.items() if flagged)
    benign = [s.id for s in bundled if not s.is_attack]
    assert sum(canon[sid] for sid in benign) == sum(base[sid] for sid in benign)
    assert sum(canon.values()) > sum(base.values())


def test_self_flushing_evicts_the_record_exactly_at_the_cap() -> None:
    # The quota holds the tool list, the note and the filler results.
    assert flood_sweep(DetectionConfig(), cap=10, floods=[0, 9, 10, 11]) == {
        0: True,
        9: True,
        10: False,
        11: False,
    }


def test_split_values_are_missed_once_no_piece_is_a_whole_value() -> None:
    assert split_sweep(DetectionConfig(), pieces=[18, 12, 6]) == {18: True, 12: False, 6: False}


def test_generator_reproduces_the_committed_scenarios(tmp_path: Path) -> None:
    subprocess.run(
        [sys.executable, str(REPO / "scripts" / "generate_adaptive.py"), str(tmp_path)],
        check=True,
        capture_output=True,
    )
    committed = sorted((REPO / "benchmarks" / "adaptive").glob("*.json"))
    assert [p.name for p in committed] == sorted(p.name for p in tmp_path.glob("*.json"))
    for path in committed:
        assert path.read_bytes() == (tmp_path / path.name).read_bytes(), path.name


def test_evaluation_script_quick_run(tmp_path: Path) -> None:
    subprocess.run(
        [
            sys.executable,
            str(REPO / "scripts" / "evaluate_week12.py"),
            "--quick",
            "--skip-embedding",
            "--injecagent",
            str(tmp_path / "none"),
            "--out",
            str(tmp_path / "a.md"),
            "--json",
            str(tmp_path / "a.json"),
            "--figures",
            str(tmp_path / "fig"),
        ],
        check=True,
        capture_output=True,
        cwd=REPO,
    )
    report = (tmp_path / "a.md").read_text(encoding="utf-8")
    assert "| default + canonical | 11/17 (65%, 41-83) | 10/17 (59%, 36-78) |" in report
    assert "## 2. Self-flushing" in report and "## 3. Splitting" in report
    ET.parse(tmp_path / "fig" / "week12-adaptive.svg")


def test_cli_canonicalize_option() -> None:
    from provmcp.cli import _detection_options

    assert _detection_options("substring,structured", "", "", None, True).canonicalize
    assert not _detection_options("substring,structured", "", "", None).canonicalize
