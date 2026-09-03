"""Console, JSON, and CSV reporting for findings."""

import csv
import io
import json
import os
import sys

SEVERITY_COLORS = {
    "critical": "\033[31;1m",  # bright red
    "high": "\033[31m",        # red
    "medium": "\033[33m",      # yellow
    "low": "\033[36m",         # cyan
}
RESET = "\033[0m"


SCHEMA_VERSION = 1


def should_color(force=None):
    """force=True/False overrides auto-detection; None means auto (TTY + NO_COLOR)."""
    if force is not None:
        return force
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def mask(value, reveal_prefix=None, reveal_suffix=None):
    if reveal_prefix is None and reveal_suffix is None:
        visible = 6
        if len(value) <= visible + 4:
            return "*" * len(value)
        return value[:visible] + "*" * max(0, len(value) - visible)

    pref_len = max(0, reveal_prefix) if reveal_prefix is not None else 0
    suff_len = max(0, reveal_suffix) if reveal_suffix is not None else 0
    val_len = len(value)

    if pref_len + suff_len >= val_len:
        return "*" * val_len

    middle_stars = val_len - pref_len - suff_len
    suffix_part = value[val_len - suff_len:] if suff_len > 0 else ""
    return value[:pref_len] + "*" * middle_stars + suffix_part


def format_console(
    findings,
    root,
    show_value=True,
    color=None,
    truncated=False,
    total_findings=None,
    reveal_prefix=None,
    reveal_suffix=None,
):
    color = should_color(force=color)
    lines = []
    for finding in sorted(findings, key=lambda f: (f["path"], f["line"])):
        severity = finding["severity"]
        tag = severity.upper().ljust(8)
        if color:
            tag = SEVERITY_COLORS[severity] + tag + RESET
        value = finding["value"][:]
        if not show_value and not finding.get("reveal"):
            value = mask(
                value,
                reveal_prefix=reveal_prefix,
                reveal_suffix=reveal_suffix,
            )
        lines.append(
            "{path}:{line} [{tag}] {rule}: {value}".format(
                path=finding["path"],
                line=finding["line"],
                tag=tag,
                rule=finding["rule"],
                value=value,
            )
        )
    lines.append("")
    summary = summarize(findings)
    if truncated:
        summary["truncated"] = total_findings - len(findings)
        summary_line = (
            "{critical} critical, {high} high, {medium} medium, {low} low — "
            "{total} total (showing {shown} of {total_findings}; "
            "{truncated} truncated)"
        ).format(
            critical=summary["critical"],
            high=summary["high"],
            medium=summary["medium"],
            low=summary["low"],
            total=summary["total"],
            shown=len(findings),
            total_findings=total_findings,
            truncated=summary["truncated"],
        )
    else:
        summary_line = (
            "{critical} critical, {high} high, {medium} medium, {low} low — "
            "{total} total"
        ).format(
            critical=summary["critical"],
            high=summary["high"],
            medium=summary["medium"],
            low=summary["low"],
            total=summary["total"],
        )
    if color:
        summary_line = (
            "\033[31m{critical}\033[0m critical, "
            "\033[31m{high}\033[0m high, "
            "\033[33m{medium}\033[0m medium, "
            "\033[36m{low}\033[0m low — {total} total"
        ).format(**summary)
    lines.append(summary_line)
    return "\n".join(lines)


def format_summary(
    findings,
    root,
    show_value=True,
    color=None,
    truncated=False,
    total_findings=None,
    reveal_prefix=None,
    reveal_suffix=None,
):
    """Render only the concise severity summary, omitting per-finding lines.

    Useful for CI logs where the full report is noise but an aggregate count
    is still wanted. Mirrors the trailing summary line of format_console.
    """

    color = should_color(force=color)
    summary = summarize(findings)
    if truncated:
        summary["truncated"] = total_findings - len(findings)
        summary_line = (
            "{critical} critical, {high} high, {medium} medium, {low} low — "
            "{total} total (showing {shown} of {total_findings}; "
            "{truncated} truncated)"
        ).format(
            critical=summary["critical"],
            high=summary["high"],
            medium=summary["medium"],
            low=summary["low"],
            total=summary["total"],
            shown=len(findings),
            total_findings=total_findings,
            truncated=summary["truncated"],
        )
    else:
        summary_line = (
            "{critical} critical, {high} high, {medium} medium, {low} low — "
            "{total} total"
        ).format(
            critical=summary["critical"],
            high=summary["high"],
            medium=summary["medium"],
            low=summary["low"],
            total=summary["total"],
        )
    if color:
        summary_line = (
            "\033[31m{critical}\033[0m critical, "
            "\033[31m{high}\033[0m high, "
            "\033[33m{medium}\033[0m medium, "
            "\033[36m{low}\033[0m low — {total} total"
        ).format(**summary)
    return summary_line


def summarize(findings):
    total = len(findings)
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in findings:
        level = counts.get(finding["severity"])
        if level is None:
            continue
        counts[finding["severity"]] = level + 1
    counts["total"] = total
    return counts


def format_json(
    findings,
    root,
    show_value=False,
    truncated=False,
    total_findings=None,
    reveal_prefix=None,
    reveal_suffix=None,
):
    ordered = sorted(findings, key=lambda f: (f["path"], f["line"], f["rule"]))
    sanitized = []
    for finding in ordered:
        item = dict(finding)
        if not show_value and not finding.get("reveal"):
            item["value"] = mask(
                item["value"],
                reveal_prefix=reveal_prefix,
                reveal_suffix=reveal_suffix,
            )
        sanitized.append(item)
    payload = {
        "schema_version": SCHEMA_VERSION,
        "root": root,
        "findings": sanitized,
    }
    if truncated:
        payload["truncated"] = True
        payload["total_findings"] = total_findings
    return json.dumps(payload, indent=2)


CSV_COLUMNS = ("path", "line", "severity", "rule", "rule_id", "value", "description")


def format_csv(
    findings,
    root,
    show_value=False,
    truncated=False,
    total_findings=None,
    reveal_prefix=None,
    reveal_suffix=None,
):
    """Render findings as a CSV table with a header row and one row per finding.

    Values are masked unless show_value is set or the finding opts in to
    reveal, matching format_json. Any tricky characters (commas, quotes,
    newlines) in secret values are quoted/escaped by the csv module.
    """

    ordered = sorted(findings, key=lambda f: (f["path"], f["line"], f["rule"]))
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(CSV_COLUMNS)
    for finding in ordered:
        value = finding["value"][:]
        if not show_value and not finding.get("reveal"):
            value = mask(
                value,
                reveal_prefix=reveal_prefix,
                reveal_suffix=reveal_suffix,
            )
        writer.writerow(
            [
                finding["path"],
                finding["line"],
                finding["severity"],
                finding["rule"],
                finding["rule_id"],
                value,
                finding["description"],
            ]
        )
    return buf.getvalue()