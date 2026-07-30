---
name: error-triage
description: Cluster a large volume of logs and stack traces into the small number of distinct root causes underneath them, ranked by share, with a redacted representative sample for each — and detect when two clusters are one bug raised from the same line, when a spike is really one retry storm, and when a failure was logged below error level where every alert rule is blind to it. Trigger when the user says "/error-triage", "cluster these logs", "how many problems are in this log", "what is actually failing", "triage these errors", or hands over a log file or directory. For root-causing one specific failure interactively use /debugging; for a single failed automation run use /failure-postmortem.
---

# Error Triage

Ten thousand log lines is not ten thousand problems. It is usually four — one of
which accounts for most of the volume — plus a long tail nobody will ever fix.

The reason nobody can see that is that no two occurrences of one bug are ever the
same string. They differ by timestamp, request id, thread, and the row that
happened to trip it. So nothing groups, everything looks equally urgent, and
triage becomes reading.

## What this is not

- **`/debugging`** takes one failure and finds its cause interactively, with a
  reproduction and hypotheses. Use it when you already know which failure matters.
- **`/failure-postmortem`** reconstructs a single failed automation run.
- This takes *many* failures and tells you how few problems they really are. It
  is the step before either of those.

## Inputs

A log file, or a directory of them:

```
python scripts/error_triage.py --input service.log --outdir out/error-triage
python scripts/error_triage.py --input logs/ --outdir out/error-triage
```

Records are reassembled before clustering, so a Python traceback split across ten
lines counts as one event rather than ten. Java `Caused by:` chains and .NET and
JS stacks are handled the same way.

`--all-levels` clusters every record rather than only the ones that read as
failures. `--top N` sets how many clusters reach the report (default 25).

## How clustering works

Each record is reduced to a template: timestamps, uuids, ip addresses, paths,
hex, quoted strings, and bare numbers become tokens. Two occurrences of one bug
then produce the same key.

Then it goes one level further. When a stack trace is present, the **deepest
non-dependency frame** leads the key — and clusters whose deepest frame lands in
the same *file* are reported as one bug. Grouping by file rather than by line is
deliberate: a pool that exhausts raises from `acquire` on one line and
`_wait_for_free` on another, and line numbers move on every edit. That is
`ET002`, and it is the finding that most changes what you do next.

## What it detects

- `ET001` **one cause accounts for most of the volume** — half or more of all
  failures share one signature. Everything else is a rounding error until it is
  fixed. High.
- `ET002` **several clusters share one origin** — different messages, same source
  file. One bug, counted many times everywhere else. High.
- `ET007` **a credential is present in the log**. High — logs have longer
  retention and wider read access than the system that issued it.
- `ET004` **a burst, not a pattern** — many occurrences inside a minute is one
  failure retrying, and counting the retries inflates it by the retry count.
- `ET003` **started partway through the window and did not stop** — a regression
  with a start time, which is far more actionable than a rate.
- `ET006` **a failure logged below error level** — every alert filtering on ERROR
  is blind to it.
- `ET008` **a trace too shallow to diagnose** — one or two frames, so the origin
  is not recoverable from the log alone.
- `ET010` **the failures are one incident, not a baseline**.
- `ET005` a long tail of one-off clusters. `ET009` too few records for the
  distribution to mean anything.

## Redaction

Representative samples are meant to be pasted into a ticket, so anything
credential-shaped is replaced with a mask — `pre…len=42 fp=ab12cd34ef56` — before
it reaches any artifact. A secret found in a log is reported, never reproduced.

Detection is the shared set in `scoutkit.redaction`, the same one `secret-sweeper`
uses. It used to be a second, smaller copy that lived here, and the copy fell
behind: it missed Google keys, Azure shared keys, URL passwords, and every
environment-variable shape from `DB_PASSWORD=` to `AWS_SECRET_ACCESS_KEY=`.
Those values were reported as no finding at all *and* copied verbatim into the
JSON. One definition, shared, is the fix.

## Limits — state these when you report

- **Clustering is textual.** Two occurrences of one bug that produce genuinely
  different messages *and* different stack origins land in separate clusters.
  The reverse also happens: two unrelated failures with generic messages
  ("operation failed") and no trace will merge.
- **`ET002` groups by source file, not by line.** That is what makes it useful,
  and it is also its failure mode: a large multi-purpose module will collect
  unrelated failures under one origin. Check the listed lines before treating
  them as one fix.
- **Records with no parseable timestamp are clustered but excluded from every
  timing finding.** A log with no timestamps yields no burst, regression, or
  incident signal at all — and the report says so rather than staying quiet.
- `ET008` deliberately ignores records with *no* stack trace. A plain error line
  is normal; a truncated trace is a swallowed cause.
- **A masked credential is not anonymous if the secret is weak.** `fp=` is
  derived with PBKDF2 and a fixed salt — expensive to search, not impossible. A
  short password or a dictionary word is still recoverable offline by someone
  holding the report. Exact lengths are withheld below 20 characters.
- **Redaction is shape-based.** A credential with no recognizable shape — a bare
  high-entropy string with no assignment around it — is not detected here and
  will appear in a sample. Run `secret-sweeper` over the source if that matters.
- Share and ranking below about twenty records are arithmetic, not evidence.
  `ET009` fires rather than letting you read significance into three data points.
- This reads what the log says. A failure that was never logged is invisible
  here, and the quietest incidents are usually that kind.

## Guardrails

Reads log files. Writes three artifacts to your output directory and nothing
else. The logs themselves are never modified. No network, no cloud writes, no
message sent anywhere.
