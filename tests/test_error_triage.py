"""Tests for error-triage.

The claim this skill makes is that a large log contains few problems. These
tests check the claim holds in the cases where it is easy to get wrong: two
messages from one line, a retry storm that looks like a rate, a failure hiding
at INFO, and a log with no timestamps at all.
"""

from __future__ import annotations

import json

import pytest

from error_triage import analyze, cluster_key, load_records, redact
from scoutkit import render_html, render_markdown
from scoutkit.io import EvidenceError


class Args:
    def __init__(self, **kw):
        self.input = kw.pop("input")
        self.all_levels = kw.pop("all_levels", False)
        self.top = kw.pop("top", 25)
        for k, v in kw.items():
            setattr(self, k, v)


def _codes(report):
    return {f.code for f in report.findings}


def _record(ts: str, message: str) -> str:
    return f"{ts} ERROR {message}\n"


DOMINANT = "".join(
    _record(f"2026-03-04T10:{m:02d}:00Z",
            f"could not acquire connection from pool after {5000 + m}ms for req-{m}")
    for m in range(30)
) + "".join(
    _record(f"2026-03-04T11:{m:02d}:00Z", f"invoice render failed for order {900 + m}")
    for m in range(4)
)


def test_occurrences_of_one_bug_form_one_cluster(write):
    report = analyze(Args(input=str(write("s.log", DOMINANT))))
    assert report.summary["clusters"] == 2
    assert report.summary["largest_cluster"] == 30


def test_a_dominant_cause_is_reported(write):
    report = analyze(Args(input=str(write("s.log", DOMINANT))))
    assert "ET001" in _codes(report)


def test_two_messages_from_one_line_are_one_bug(write):
    log = (
        "2026-03-04T10:00:00Z ERROR order lookup failed\n"
        'Traceback (most recent call last):\n'
        '  File "app/db/pool.py", line 88, in acquire\n'
        "OperationalError: connection closed\n"
        "2026-03-04T10:05:00Z ERROR could not acquire connection\n"
        'Traceback (most recent call last):\n'
        '  File "app/db/pool.py", line 88, in acquire\n'
        "TimeoutError: pool exhausted\n"
    )
    report = analyze(Args(input=str(write("s.log", log))))
    assert "ET002" in _codes(report)
    shared = report.sections["shared_origins"]
    assert shared and "pool.py" in shared[0]["origin"]


def test_unrelated_origins_do_not_merge(write):
    log = (
        "2026-03-04T10:00:00Z ERROR alpha failed\n"
        'Traceback (most recent call last):\n'
        '  File "app/a.py", line 10, in run\n'
        "ValueError: bad\n"
        "2026-03-04T10:05:00Z ERROR beta failed\n"
        'Traceback (most recent call last):\n'
        '  File "app/b.py", line 20, in run\n'
        "ValueError: bad\n"
    )
    assert "ET002" not in _codes(analyze(Args(input=str(write("s.log", log)))))


def test_two_lines_in_one_file_are_one_origin(write):
    """Line numbers move on every edit; the file is the stable unit."""
    log = (
        "2026-03-04T10:00:00Z ERROR could not acquire connection\n"
        'Traceback (most recent call last):\n'
        '  File "app/db/pool.py", line 140, in _wait_for_free\n'
        "TimeoutError: pool exhausted\n"
        "2026-03-04T10:05:00Z ERROR order lookup failed\n"
        'Traceback (most recent call last):\n'
        '  File "app/db/pool.py", line 88, in acquire\n'
        "OperationalError: connection closed\n"
    )
    report = analyze(Args(input=str(write("s.log", log))))
    assert "ET002" in _codes(report)
    assert len(report.sections["shared_origins"][0]["lines"]) == 2


def test_a_retry_storm_is_reported_as_a_burst(write):
    log = "".join(
        _record(f"2026-03-04T10:00:{s:02d}Z", f"webhook delivery refused attempt {s}")
        for s in range(0, 40, 5)
    )
    assert "ET004" in _codes(analyze(Args(input=str(write("s.log", log)))))


def test_the_same_error_spread_over_hours_is_not_a_burst(write):
    log = "".join(
        _record(f"2026-03-04T{h:02d}:00:00Z", f"webhook delivery refused attempt {h}")
        for h in range(10, 18)
    )
    assert "ET004" not in _codes(analyze(Args(input=str(write("s.log", log)))))


def test_a_failure_logged_at_info_is_reported(write):
    log = DOMINANT + "2026-03-04T12:00:00Z INFO nightly export failed for batch 12\n"
    report = analyze(Args(input=str(write("s.log", log))))
    assert "ET006" in _codes(report)


def test_a_genuine_info_line_is_not_reported(write):
    log = DOMINANT + "2026-03-04T12:00:00Z INFO request completed in 41ms\n"
    report = analyze(Args(input=str(write("s.log", log))))
    mislabeled = [f for f in report.findings if f.code == "ET006"]
    assert not mislabeled


def test_a_regression_that_starts_partway_and_continues_is_reported(write):
    early = "".join(_record(f"2026-03-04T10:{m:02d}:00Z", f"steady state noise {m}")
                    for m in range(0, 30, 3))
    late = "".join(_record(f"2026-03-04T11:{m:02d}:00Z", f"new failure mode {m}")
                   for m in range(30, 60, 5))
    report = analyze(Args(input=str(write("s.log", early + late))))
    assert "ET003" in _codes(report)


def test_a_shallow_trace_is_reported(write):
    log = (
        "2026-03-04T10:00:00Z ERROR worker died\n"
        'Traceback (most recent call last):\n'
        '  File "app/worker.py", line 44, in tick\n'
        "KeyError: 'tenant_id'\n"
    )
    assert "ET008" in _codes(analyze(Args(input=str(write("s.log", log)))))


def test_a_plain_error_line_without_a_trace_is_not_called_shallow(write):
    """No trace is normal. A truncated trace is a swallowed cause."""
    log = "".join(_record(f"2026-03-04T10:{m:02d}:00Z", f"disk write refused {m}")
                  for m in range(6))
    assert "ET008" not in _codes(analyze(Args(input=str(write("s.log", log)))))


def test_too_few_records_is_reported_rather_than_ranked_confidently(write):
    log = "".join(_record(f"2026-03-04T10:0{m}:00Z", f"thing {m} failed") for m in range(3))
    assert "ET009" in _codes(analyze(Args(input=str(write("s.log", log)))))


# --- redaction -------------------------------------------------------------

def test_a_credential_in_the_log_is_reported(write):
    log = DOMINANT + "2026-03-04T12:00:00Z ERROR auth rejected token=abc123def456 user=svc\n"
    report = analyze(Args(input=str(write("s.log", log))))
    assert "ET007" in _codes(report)


def test_the_credential_value_never_reaches_any_artifact(write):
    secret = "abc123def456"
    log = DOMINANT + f"2026-03-04T12:00:00Z ERROR auth rejected token={secret} user=svc\n"
    report = analyze(Args(input=str(write("s.log", log))))
    rendered = "\n".join([
        json.dumps(report.to_dict()),
        render_markdown(report, title="t"),
        render_html(report, title="t"),
    ])
    assert secret not in rendered


def test_a_placeholder_token_is_not_reported_as_a_credential(write):
    log = DOMINANT + "2026-03-04T12:00:00Z ERROR auth rejected token=your-api-key user=svc\n"
    assert "ET007" not in _codes(analyze(Args(input=str(write("s.log", log)))))


def test_redact_leaves_ordinary_text_alone():
    assert redact("connection refused to db-1") == "connection refused to db-1"


# --- inputs ----------------------------------------------------------------

def test_a_directory_of_logs_is_read(tmp_path):
    (tmp_path / "a.log").write_text(_record("2026-03-04T10:00:00Z", "alpha failed"), encoding="utf-8")
    (tmp_path / "b.log").write_text(_record("2026-03-04T10:01:00Z", "beta failed"), encoding="utf-8")
    report = analyze(Args(input=str(tmp_path)))
    assert report.summary["sources"] == 2


def test_a_log_with_no_timestamps_still_clusters(write):
    log = "ERROR widget exploded\nERROR widget exploded\nERROR gizmo jammed\n"
    report = analyze(Args(input=str(write("s.log", log))))
    assert report.summary["clusters"] == 2
    assert report.summary["window_seconds"] == 0


def test_a_log_with_no_failures_says_so_instead_of_inventing_clusters(write):
    log = "2026-03-04T10:00:00Z INFO request completed in 41ms\n" * 5
    report = analyze(Args(input=str(write("s.log", log))))
    assert report.summary["failures"] == 0
    assert any("none of them are failures" in n for n in report.notes)


def test_all_levels_clusters_everything(write):
    log = "2026-03-04T10:00:00Z INFO request completed in 41ms\n" * 5
    report = analyze(Args(input=str(write("s.log", log)), all_levels=True))
    assert report.summary["failures"] == 5


def test_a_missing_path_is_an_evidence_error(tmp_path):
    with pytest.raises(EvidenceError):
        analyze(Args(input=str(tmp_path / "absent.log")))


def test_an_empty_log_is_an_evidence_error(write):
    with pytest.raises(EvidenceError):
        analyze(Args(input=str(write("s.log", "\n\n"))))


def test_cluster_key_ignores_the_level_word():
    a = cluster_key({"head": "2026-03-04T10:00:00Z ERROR pool exhausted", "origin": ""})
    b = cluster_key({"head": "2026-03-04T11:00:00Z FATAL pool exhausted", "origin": ""})
    assert a == b


def test_a_traceback_counts_as_one_record(write):
    log = (
        "2026-03-04T10:00:00Z ERROR upload failed\n"
        "Traceback (most recent call last):\n"
        '  File "app/upload.py", line 12, in send\n'
        '  File "app/net.py", line 40, in post\n'
        "ConnectionError: refused\n"
    )
    assert len(load_records(str(write("s.log", log)))) == 1


# --- the bundled template --------------------------------------------------

def test_the_bundled_template_runs(template):
    report = analyze(Args(input=str(template("error-triage", "service.example.log"))))
    codes = _codes(report)
    assert "ET002" in codes          # two messages from app/db/pool.py:88
    assert "ET006" in codes          # nightly export failed, logged at INFO
    assert "ET007" in codes          # token= in the log
    assert report.summary["failures"] > 20


def test_report_is_reproducible(write):
    path = write("s.log", DOMINANT)
    assert analyze(Args(input=str(path))).to_dict() == analyze(Args(input=str(path))).to_dict()
