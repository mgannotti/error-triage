#!/usr/bin/env python3
"""error-triage — the pile of errors, and the handful of causes underneath it.

Ten thousand log lines is not ten thousand problems. It is usually four, one of
which accounts for most of the volume, plus a long tail nobody will ever fix.
But every occurrence carries a different timestamp, request id, and row that
happened to trip it, so nothing groups and the shape stays hidden.

This normalizes each record to a template, clusters on that, and then goes one
level further: two clusters whose deepest application frame is the same file and
line are one bug wearing two error messages.

Offline. Read-only. The logs are evidence and are never modified.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from scoutkit import (  # noqa: E402
    Finding,
    Report,
    Severity,
    credential_spans,
    deepest_application_frame,
    iter_text_files,
    level_of,
    looks_like_placeholder,
    mask,
    normalize_line,
    read_text,
    redact_text,
    split_records,
    stack_frames,
    truncate,
)
from scoutkit.cli import run  # noqa: E402
from scoutkit.io import EvidenceError  # noqa: E402

SKILL = "error-triage"
TITLE = "Error Triage — how many problems are actually in this log"

# Below this many records the shape of a distribution is not evidence of anything.
MIN_RECORDS = 20
# A cluster holding this share of all errors is the one to fix first.
DOMINANT_SHARE = 0.50
# Occurrences this close together are one incident retrying, not separate events.
RETRY_WINDOW_SECONDS = 60
RETRY_MIN_OCCURRENCES = 5
# A trace with fewer frames than this cannot be diagnosed from the log alone.
SHALLOW_TRACE = 2

ERROR_LEVELS = frozenset({"ERROR", "ERR", "SEVERE", "FATAL", "CRITICAL"})
QUIET_LEVELS = frozenset({"INFO", "INFORMATION", "DEBUG", "TRACE", "NOTICE"})

# Text that means a failure regardless of the level it was logged at.
_FAILURE_TEXT = re.compile(
    r"\b(?:exception|traceback|stack\s?trace|panic|segfault|fatal|"
    r"failed|failure|refused|denied|timed?\s?out|timeout|unreachable|"
    r"unhandled|uncaught|abort(?:ed)?|crash(?:ed)?|deadlock|"
    r"5\d{2}\s+(?:internal|bad\s+gateway|service\s+unavailable))\b",
    re.IGNORECASE,
)

# Credential shapes worth catching *in the log itself*. A log that records a
# token has copied a secret into a system with different retention and different
# access control than the one that issued it.
#
# Detection lives in scoutkit.redaction, shared with secret-sweeper. It used to
# live here as a second, smaller copy, and the copy fell behind: it missed
# Google keys, Azure shared keys, URL passwords, and — because it anchored the
# keyword with `\b`, which cannot match after an underscore — every environment
# variable shape from `DB_PASSWORD=` to `AWS_SECRET_ACCESS_KEY=`. Those values
# were reported as no finding at all *and* reproduced verbatim in the sample.


def redact(text: str) -> str:
    """Replace anything credential-shaped with its mask, in place.

    A representative sample is only useful if it can be pasted into a ticket.
    Reproducing a token in the artifact would move the secret rather than
    report it.
    """
    return redact_text(text or "")

_TIMESTAMP = re.compile(
    r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
)


def _parse_timestamp(text: str) -> datetime | None:
    match = _TIMESTAMP.search(text or "")
    if not match:
        return None
    raw = match.group(1).replace(",", ".").replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def redact(text: str) -> str:
    """Replace anything credential-shaped with its mask, in place.

    A representative sample is only useful if it can be pasted into a ticket.
    Reproducing a token in the artifact would move the secret rather than
    report it.
    """
    return redact_text(text or "")


def _is_failure(record: list[str]) -> bool:
    head = record[0] if record else ""
    if level_of(head).upper() in ERROR_LEVELS:
        return True
    body = "\n".join(record[:4])
    return bool(_FAILURE_TEXT.search(body))


def load_records(path: str) -> list[dict[str, Any]]:
    """Read one log file or a directory of them into normalized records."""
    target = Path(path)
    if not target.exists():
        raise EvidenceError(f"no such path: {target}")

    sources = list(iter_text_files(target, suffixes={".log", ".txt", ".out", ".err", ".json"})) \
        if target.is_dir() else [target]
    if not sources:
        raise EvidenceError(f"no log files found under {target}")

    records: list[dict[str, Any]] = []
    for source in sorted(sources):
        text = read_text(source)
        for lines in split_records(text):
            body = "\n".join(lines)
            frames = stack_frames(body)
            deepest = deepest_application_frame(frames)
            records.append({
                "source": source.name,
                "lines": lines,
                "head": lines[0],
                "level": level_of(lines[0]).upper(),
                "when": _parse_timestamp(body),
                "frames": len(frames),
                "origin": deepest.label if deepest else "",
                "origin_file": deepest.location if deepest else "",
                "failure": _is_failure(lines),
            })
    if not records:
        raise EvidenceError(f"no log records found in {target}")
    return records


def cluster_key(record: dict[str, Any]) -> str:
    """The template two occurrences of one bug share.

    The message alone is not enough: two different messages raised from the same
    line are the same bug. When an application frame is available it leads the
    key, so those collapse together.
    """
    message = normalize_line(record["head"])
    # Drop the level word so the same failure logged at ERROR and FATAL matches.
    message = re.sub(r"\b(?:TRACE|DEBUG|INFO|WARN|WARNING|ERROR|ERR|SEVERE|FATAL|CRITICAL)\b",
                     "", message).strip()
    if record["origin"]:
        return f"{record['origin']} :: {message[:120]}"
    return message[:160]


def _find_credentials(records: list[dict[str, Any]]) -> list[tuple[str, str]]:
    """(source, masked) for every credential-shaped value present in the logs.

    Uses the same detection set as the redaction that protects the samples, so
    a value can never be reproduced in a sample while going unreported here —
    which is exactly what happened while this engine carried its own patterns.
    """
    seen: dict[str, str] = {}
    for record in records:
        body = "\n".join(record["lines"])
        for start, end in credential_spans(body):
            value = body[start:end]
            if looks_like_placeholder(value):
                continue
            seen.setdefault(mask(value), record["source"])
    return sorted((source, masked) for masked, source in seen.items())


def analyze(args: argparse.Namespace) -> Report:
    records = load_records(args.input)
    include_all = bool(getattr(args, "all_levels", False))
    failures = records if include_all else [r for r in records if r["failure"]]

    if not failures:
        report = Report(skill=SKILL, subject=Path(args.input).name)
        report.summary = {"records": len(records), "failures": 0, "clusters": 0}
        report.note(f"{len(records)} record(s) read and none of them are failures. "
                    f"Pass --all-levels to cluster everything regardless of level.")
        report.decide_verdict()
        return report

    report = Report(skill=SKILL, subject=Path(args.input).name)

    def add(code: str, severity: str, title: str, detail: str, locator: str, fix: str,
            evidence: str = "") -> None:
        report.add(Finding(code=code, severity=severity, title=title, detail=detail,
                           locator=locator, evidence=evidence, recommendation=fix))

    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in failures:
        grouped[cluster_key(record)].append(record)

    clusters: list[dict[str, Any]] = []
    for key, members in grouped.items():
        stamps = sorted(m["when"] for m in members if m["when"])
        origins = Counter(m["origin"] for m in members if m["origin"])
        files = Counter(m["origin_file"] for m in members if m["origin_file"])
        clusters.append({
            "signature": key,
            "count": len(members),
            "share": round(len(members) / len(failures), 4),
            "first_seen": stamps[0].isoformat() if stamps else None,
            "last_seen": stamps[-1].isoformat() if stamps else None,
            "origin": origins.most_common(1)[0][0] if origins else "",
            "origin_file": files.most_common(1)[0][0] if files else "",
            "levels": sorted({m["level"] for m in members if m["level"]}),
            "sources": sorted({m["source"] for m in members}),
            "max_frames": max(m["frames"] for m in members),
            "sample": redact(truncate("\n".join(members[0]["lines"][:6]), 600)),
        })
    clusters.sort(key=lambda c: (-c["count"], c["signature"]))

    total_stamps = sorted(r["when"] for r in failures if r["when"])
    window_seconds = ((total_stamps[-1] - total_stamps[0]).total_seconds()
                      if len(total_stamps) > 1 else 0.0)

    top = clusters[0]
    if top["share"] >= DOMINANT_SHARE and len(clusters) > 1:
        add("ET001", Severity.HIGH, "One cause accounts for most of the volume",
            f"{top['count']} of {len(failures)} failures ({top['share']:.0%}) share a single "
            f"signature. Everything else in this log is a rounding error until this one is fixed.",
            top["origin"] or truncate(top["signature"], 60),
            "Fix this cluster first, then re-run and see what the log actually looks like.",
            top["sample"])

    # Two clusters raised from the same module are one bug with two messages.
    # Grouping on the file rather than file:line is deliberate: a pool that
    # exhausts raises from `acquire` on one line and from `_wait_for_free` on
    # another, and line numbers move every time the file is edited.
    by_origin: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for cluster in clusters:
        if cluster["origin_file"]:
            by_origin[cluster["origin_file"]].append(cluster)
    for origin, group in sorted(by_origin.items()):
        if len(group) < 2:
            continue
        combined = sum(c["count"] for c in group)
        lines_hit = sorted({c["origin"] for c in group if c["origin"]})
        where = f" ({', '.join(lines_hit)})" if len(lines_hit) > 1 else ""
        add("ET002", Severity.HIGH, "Several clusters share one origin",
            f"{len(group)} distinct error messages ({combined} occurrences) all originate in "
            f"{origin}{where}. These are counted separately everywhere else and they are one bug.",
            origin,
            "Treat them as one item. Fixing the origin retires every message above it.",
            " | ".join(truncate(c['signature'], 70) for c in group[:3]))

    for cluster in clusters:
        if cluster["count"] < RETRY_MIN_OCCURRENCES or not cluster["first_seen"]:
            continue
        first = datetime.fromisoformat(cluster["first_seen"])
        last = datetime.fromisoformat(cluster["last_seen"])
        span = (last - first).total_seconds()
        if span <= RETRY_WINDOW_SECONDS:
            add("ET004", Severity.MEDIUM, "A burst, not a pattern",
                f"{cluster['count']} occurrences inside {span:.0f} seconds. This is one failure "
                f"being retried, and counting the retries makes it look {cluster['count']}× worse "
                f"than it is.",
                cluster["origin"] or truncate(cluster["signature"], 60),
                "Count this as one incident. Check whether the retry policy has a backoff.",
                cluster["sample"])

    # A cluster that begins partway through the window and does not stop is a
    # regression with a start time, which is far more actionable than a rate.
    if len(total_stamps) > 1 and window_seconds > 0:
        start = total_stamps[0]
        for cluster in clusters:
            if cluster["count"] < 3 or not cluster["first_seen"]:
                continue
            first = datetime.fromisoformat(cluster["first_seen"])
            last = datetime.fromisoformat(cluster["last_seen"])
            offset = (first - start).total_seconds()
            covers_the_end = (total_stamps[-1] - last).total_seconds() <= window_seconds * 0.1
            if offset >= window_seconds * 0.25 and covers_the_end:
                add("ET003", Severity.MEDIUM, "This one started partway through and did not stop",
                    f"First seen at {cluster['first_seen']}, {offset / 60:.0f} minutes into the "
                    f"window, and still occurring at the end. Something changed at that point; "
                    f"the log says when.",
                    cluster["origin"] or truncate(cluster["signature"], 60),
                    "Look at what deployed or changed around that timestamp.",
                    cluster["sample"])

    mislabeled = [c for c in clusters if c["levels"] and not (set(c["levels"]) & ERROR_LEVELS)
                  and set(c["levels"]) & QUIET_LEVELS]
    for cluster in mislabeled:
        add("ET006", Severity.MEDIUM, "A failure logged below error level",
            f"{cluster['count']} occurrence(s) logged at {'/'.join(cluster['levels'])} despite "
            f"reading as a failure. Every alert rule and dashboard filtering on ERROR is blind "
            f"to this.",
            cluster["origin"] or truncate(cluster["signature"], 60),
            "Raise the level at the call site, or confirm it is genuinely not a failure.",
            cluster["sample"])

    undiagnosable = [c for c in clusters if c["max_frames"] and c["max_frames"] <= SHALLOW_TRACE]
    for cluster in undiagnosable[:5]:
        add("ET008", Severity.MEDIUM, "A trace too shallow to diagnose",
            f"{cluster['count']} occurrence(s) with at most {cluster['max_frames']} stack frame(s). "
            f"There is not enough here to find the origin, so this cluster cannot be actioned "
            f"from the log alone.",
            truncate(cluster["signature"], 60),
            "Log the full traceback at the catch site, or stop swallowing the cause.",
            cluster["sample"])

    credentials = _find_credentials(failures)
    for source, masked in credentials:
        add("ET007", Severity.HIGH, "A credential is present in the log",
            f"A credential-shaped value appears in {source}. Logs have longer retention and "
            f"wider read access than the system that issued it, so this has moved the secret "
            f"somewhere less protected.",
            source,
            "Redact at the logging call, then rotate the credential — it is already in every "
            "copy of this log, including the backups.",
            masked)

    singletons = [c for c in clusters if c["count"] == 1]
    if singletons and len(singletons) >= max(3, len(clusters) * 0.5):
        add("ET005", Severity.LOW, "A long tail of one-off errors",
            f"{len(singletons)} of {len(clusters)} clusters occurred exactly once. These are "
            f"where effort goes to die: each looks urgent alone and none of them is.",
            f"{len(singletons)} clusters",
            "Set them aside until one recurs. Recurrence is the signal, not novelty.")

    if len(failures) < MIN_RECORDS:
        add("ET009", Severity.LOW, "Too few records for the distribution to mean anything",
            f"{len(failures)} failure record(s). Shares and rankings computed from this are "
            f"arithmetic, not evidence.",
            f"{len(failures)} records",
            "Collect a longer window before acting on the ordering below.")

    hours = Counter(
        datetime.fromisoformat(c["first_seen"]).strftime("%Y-%m-%dT%H")
        for c in clusters if c["first_seen"]
    )
    if window_seconds > 3600 and hours:
        busiest, busiest_count = hours.most_common(1)[0]
        if busiest_count >= max(3, len(clusters) * 0.6):
            add("ET010", Severity.MEDIUM, "The failures are one incident, not a baseline",
                f"{busiest_count} of {len(clusters)} clusters first appeared in the hour beginning "
                f"{busiest}. This log is describing an event, and treating it as a steady-state "
                f"error rate will misdirect the fix.",
                busiest,
                "Find what happened in that hour before triaging the clusters individually.")

    report.sections = {
        "clusters": clusters[: int(getattr(args, "top", 25) or 25)],
        "timeline": [{"hour": hour, "clusters_started": count}
                     for hour, count in sorted(hours.items())],
        "shared_origins": [
            {"origin": origin, "clusters": len(group),
             "occurrences": sum(c["count"] for c in group),
             "lines": sorted({c["origin"] for c in group if c["origin"]})}
            for origin, group in sorted(by_origin.items()) if len(group) > 1
        ],
        "credentials_present": [{"source": s, "masked": m} for s, m in credentials],
    }
    report.summary = {
        "records": len(records),
        "failures": len(failures),
        "clusters": len(clusters),
        "singletons": len(singletons),
        "largest_cluster": top["count"],
        "largest_share": f"{top['share']:.0%}",
        "window_seconds": int(window_seconds),
        "sources": len({r["source"] for r in records}),
    }
    report.note("Clustering is textual. Two occurrences of one bug that produce genuinely "
                "different messages and different stack origins will land in separate clusters.")
    report.note("Clusters are grouped into one origin by source file, not by line, because line "
                "numbers move on every edit. A large multi-purpose module can therefore collect "
                "unrelated failures under one origin.")
    report.note("Records without a parseable timestamp are clustered but excluded from every "
                "timing finding, so a log with no timestamps yields no burst or regression signal.")
    report.note("Samples and any credential-shaped values are masked before they reach the "
                "artifacts. No secret found in a log is reproduced in this report.")
    report.note("Nothing is written back to the logs. This reads them.")
    report.decide_verdict()
    return report


def _extend(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--all-levels", action="store_true",
                        help="cluster every record, not only the ones that read as failures")
    parser.add_argument("--top", type=int, default=25,
                        help="how many clusters to include in the report (default: 25)")


def main(argv: list[str] | None = None) -> int:
    return run(
        argv, skill=SKILL, title=TITLE,
        description="Cluster a pile of logs into distinct root causes with representative samples.",
        analyze=analyze, extend=_extend,
    )


if __name__ == "__main__":
    raise SystemExit(main())
