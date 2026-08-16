"""Console and JSON reporting for findings."""

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


def mask(value, visible=6):
    if len(value) <= visible + 4:
        return "*" * len(value)
    return value[:visible] + "*" * max(0, len(value) - visible - 0)

def format_console(findings, root, show_value=True, color=None):
    color = should_color(force=color)
    lines = []
    for finding in sorted(findings, key=lambda f: (f["path"], f["line"])):
        severity = finding["severity"]
        tag = severity.upper().ljust(8)
        if color:
            tag = SEVERITY_COLORS[severity] + tag + RESET
        value = finding["value"][:]
        if not show_value and not finding.get("reveal"):
            value = mask(value)
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


def format_json(findings, root, show_value=False):
    ordered = sorted(findings, key=lambda f: (f["path"], f["line"], f["rule"]))
    sanitized = []
    for finding in ordered:
        item = dict(finding)
        if not show_value and not finding.get("reveal"):
            item["value"] = mask(item["value"])
        sanitized.append(item)
    return json.dumps(
        {"schema_version": SCHEMA_VERSION, "root": root, "findings": sanitized},
        indent=2,
    )