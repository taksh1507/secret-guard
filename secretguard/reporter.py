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


def format_sarif(findings, root, show_value=False, version="0.6.0", custom_rules=None):
    from .rules import RULES, SPECIAL_RULES

    # Build a map of all known rule metadata
    all_rules_dict = {}
    for r in RULES:
        all_rules_dict[r["id"]] = {
            "id": r["id"],
            "name": r["name"],
            "severity": r["severity"],
            "description": r.get("description", ""),
        }
    for r_id, r in SPECIAL_RULES.items():
        all_rules_dict[r_id] = {
            "id": r_id,
            "name": r["name"],
            "severity": r["severity"],
            "description": r.get("description", ""),
        }
    if custom_rules:
        for r in custom_rules:
            all_rules_dict[r["id"]] = {
                "id": r["id"],
                "name": r["name"],
                "severity": r["severity"],
                "description": r.get("description", ""),
            }

    # Gather rules mentioned in findings but not in our dictionary
    for f in findings:
        r_id = f.get("rule_id")
        if r_id and r_id not in all_rules_dict:
            all_rules_dict[r_id] = {
                "id": r_id,
                "name": f.get("rule", r_id),
                "severity": f.get("severity", "medium"),
                "description": f.get("description", ""),
            }

    # Map severities to SARIF level configurations
    severity_map = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
    }

    # Format the rules array for the SARIF run
    sarif_rules = []
    for r_id in sorted(all_rules_dict.keys()):
        r = all_rules_dict[r_id]
        level = severity_map.get(r["severity"].lower(), "warning")
        rule_obj = {
            "id": r["id"],
            "name": r["name"],
            "shortDescription": {"text": r["name"]},
            "fullDescription": {"text": r["description"] or r["name"]},
            "defaultConfiguration": {"level": level},
        }
        sarif_rules.append(rule_obj)

    # Format the results array
    sarif_results = []
    for f in sorted(
        findings, key=lambda x: (x["path"], x["line"], x.get("rule_id", ""))
    ):
        r_id = f.get("rule_id", "generic-secret-key")
        r_name = f.get("rule", "Generic Secret Key")
        line = f.get("line", 1)
        path = f.get("path", "")
        severity = f.get("severity", "medium")

        # Mask the value if not show_value
        val = f["value"][:]
        if not show_value and not f.get("reveal"):
            val = mask(val)

        msg_text = f"{r_name}: {val}"
        rel_path = path.replace("\\", "/")

        result_obj = {
            "ruleId": r_id,
            "level": severity_map.get(severity.lower(), "warning"),
            "message": {"text": msg_text},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": rel_path},
                        "region": {"startLine": line, "startColumn": 1},
                    }
                }
            ],
        }
        sarif_results.append(result_obj)

    sarif_data = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "secret-guard",
                        "version": version,
                        "rules": sarif_rules,
                    }
                },
                "results": sarif_results,
            }
        ],
    }
    return json.dumps(sarif_data, indent=2)