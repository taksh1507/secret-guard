"""Command-line interface for secret-guard."""

import argparse
import hashlib
import json
import os
import subprocess
import sys

from . import __version__
from .reporter import format_console, format_json
from .rules import (
    RULES,
    SPECIAL_RULES,
    RuleManifestError,
    compile_custom_rules,
    known_rule_ids,
    load_rules_file,
    unknown_rule_ids,
)
from .scanner import Scanner


def install_hook(target=".git/hooks/pre-commit"):
    """Write a pre-commit hook that runs secret-guard on staged files."""

    root = os.getcwd()
    hook_path = os.path.join(root, target)
    hook_dir = os.path.dirname(hook_path)
    if not os.path.isdir(hook_dir):
        print(f"No {hook_dir} directory found. Is {root} a git repo?")
        return 1

    script = (
        "#!/bin/sh\n"
        "# Installed by secret-guard. Scans staged files for leaked secrets.\n"
        "exec secret-guard scan --staged\n"
    )
    with open(hook_path, "w", encoding="utf-8") as handle:
        handle.write(script)
    os.chmod(hook_path, 0o755)
    print(f"Pre-commit hook installed at {hook_path}")
    return 0


def find_config(start_path):
    """Search upwards from start_path for secret-guard.json."""

    curr = os.path.abspath(start_path)
    if os.path.isfile(curr):
        curr = os.path.dirname(curr)
    while True:
        config_file = os.path.join(curr, CONFIG_FILENAME)
        if os.path.isfile(config_file):
            return config_file
        parent = os.path.dirname(curr)
        if parent == curr:
            break
        curr = parent
    return None


CONFIG_FILENAME = "secret-guard.json"
KNOWN_CONFIG_KEYS = {
    "//",
    "exclude",
    "no_entropy",
    "skip_rules",
    "only_rules",
    "rules",
    "baseline",
    "severity",
}


def _config_fatal(message):
    print(message, file=sys.stderr)
    sys.exit(2)


def _require_list_of(data, key, expected_type, kind, config_path):
    """Exit(2) unless data[key] is a list of expected_type items."""

    value = data.get(key)
    if value is None:
        return
    if not isinstance(value, list) or not all(
        isinstance(x, expected_type) for x in value
    ):
        _config_fatal(
            f"Error: '{key}' in {config_path} must be a list of {kind}."
        )


def load_config(config_path):
    """Load and validate secret-guard.json."""

    try:
        with open(config_path, encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        _config_fatal(f"Error parsing {config_path}: {e}")
    except OSError as e:
        _config_fatal(f"Error reading {config_path}: {e}")

    if not isinstance(data, dict):
        _config_fatal(
            "Error: configuration root in "
            f"{config_path} must be a JSON object."
        )

    for key in data:
        if key not in KNOWN_CONFIG_KEYS:
            print(
                f"Warning: Unknown configuration key '{key}' in "
                f"{config_path}",
                file=sys.stderr,
            )

    _require_list_of(data, "exclude", str, "strings", config_path)
    if "no_entropy" in data and not isinstance(data["no_entropy"], bool):
        _config_fatal(
            f"Error: 'no_entropy' in {config_path} must be a boolean."
        )
    _require_list_of(data, "skip_rules", str, "strings", config_path)
    _require_list_of(data, "only_rules", str, "strings", config_path)
    _require_list_of(data, "baseline", dict, "objects", config_path)
    if "severity" in data and data["severity"] not in {
        "low",
        "medium",
        "high",
        "critical",
    }:
        _config_fatal(
            f"Error: 'severity' in {config_path} must be one of: "
            "low, medium, high, critical."
        )
    return data


def build_parser():
    parser = argparse.ArgumentParser(
        prog="secret-guard",
        description="Scan your codebase for hardcoded secrets before they leak.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    subparsers = parser.add_subparsers(dest="command")

    scan = subparsers.add_parser(
        "scan", help="Scan files for secrets."
    )
    scan.add_argument("path", nargs="?", default=".", help="Path to scan (default: .)")
    scan.add_argument(
        "--exclude", action="append", default=[],
        metavar="DIR", help="Additional directory names to skip (repeatable).",
    )
    scan.add_argument(
        "--no-entropy", action="store_true",
        help="Disable high-entropy string detection.",
    )
    scan.add_argument(
        "--json", action="store_true", help="Output JSON instead of a report.",
    )
    scan.add_argument(
        "--show-value", action="store_true",
        help="Print full secret values (default masks them). Takes precedence over --reveal-prefix and --reveal-suffix.",
    )
    scan.add_argument(
        "--reveal-prefix", type=int, default=None, metavar="N",
        help="Show first N characters of the masked secret. Ignored if --show-value is set.",
    )
    scan.add_argument(
        "--reveal-suffix", type=int, default=None, metavar="N",
        help="Show last N characters of the masked secret. Ignored if --show-value is set.",
    )
    scan.add_argument(
        "--no-color", action="store_true",
        help="Disable colored console output.",
    )
    scan.add_argument(
        "--staged", action="store_true",
        help="Scan only files staged in git.",
    )
    scan.add_argument(
        "--baseline", metavar="FILE",
        help="Path to a baseline file containing allowed/suppressed secrets.",
    )
    scan.add_argument(
        "--severity",
        choices=["low", "medium", "high", "critical"],
        default=None,
        help="Minimum severity threshold to fail the scan (default: low).",
    )
    scan.add_argument(
        "--max-findings", type=int, default=None, metavar="N",
        help="Cap the number of findings printed/returned to N. The scan still "
             "reports the full summary and exits non-zero when secrets are found.",
    )
    scan.add_argument(
        "--skip-rule", action="append", default=[], metavar="RULE",
        help="Never run the given rule id (repeatable). Mixes with --only-rule.",
    )
    scan.add_argument(
        "--only-rule", action="append", default=[], metavar="RULE",
        help="Run only the given rule id (repeatable).",
    )
    scan.add_argument(
        "--rules-path", metavar="FILE",
        help="Path to a JSON manifest of custom rules to add to the built-ins.",
    )
    scan.add_argument(
        "--list-rules", action="store_true",
        help="List every available rule id and exit.",
    )
    scan.add_argument(
        "--stdin", action="store_true",
        help="Read content to scan from stdin instead of a path on disk.",
    )
    scan.add_argument(
        "--filename", default="stdin", metavar="NAME",
        help="Reported path for --stdin input (default: stdin).",
    )
    scan.set_defaults(func=cmd_scan)

    hooks = subparsers.add_parser(
        "install-hook", help="Install a git pre-commit hook."
    )
    hooks.set_defaults(func=cmd_install_hook)

    init = subparsers.add_parser(
        "init", help="Initialize a starter configuration file."
    )
    init.set_defaults(func=cmd_init)

    return parser


def staged_files():
    result = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        print("git is not available or not a repository.", file=sys.stderr)
        return []
    return [line for line in result.stdout.splitlines() if line]


def staged_content(path):
    """Return the content of a file from the git index (the staged blob).

    Reads from the index rather than the working tree, so a secret that was
    staged but then changed or deleted locally is still detected.
    """

    result = subprocess.run(
        ["git", "show", ":" + path],
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        return None
    try:
        return result.stdout.decode("utf-8", errors="replace")
    except (OSError, ValueError):
        return None


def list_rules(custom_rules=None):
    """Print every available rule id with name, severity, and description."""

    def fmt(info):
        return "  {:<30} {:<30} {:>8}  {}".format(
            info["id"], info["name"], info["severity"].upper(), info["description"]
)

    print("Regex rules:")
    for rule in RULES:
        print(fmt(rule))
    if custom_rules:
        print("\nCustom rules:")
        for rule in custom_rules:
            print(fmt(rule))
    print("\nSpecial rules:")
    for info in SPECIAL_RULES.values():
        print(fmt(info))
    return 0


def filter_baseline(findings, baseline):
    if not baseline:
        return findings

    filtered = []
    for f in findings:
        val_hash = hashlib.sha256(f["value"].encode("utf-8")).hexdigest()
        is_suppressed = False
        for entry in baseline:
            entry_path = entry.get("path", "").replace("\\", "/")
            f_path = f["path"].replace("\\", "/")
            if entry_path == f_path and entry.get("rule_id") == f.get("rule_id"):
                if "hash" in entry:
                    if entry["hash"] == val_hash:
                        is_suppressed = True
                        break
                else:
                    is_suppressed = True
                    break
        if not is_suppressed:
            filtered.append(f)
    return filtered


def resolve_baseline(args, config):
    """Return the list of suppressed findings from CLI --baseline or config."""

    baseline_path = getattr(args, "baseline", None)
    if baseline_path:
        try:
            with open(baseline_path, encoding="utf-8") as f:
                return json.load(f).get("baseline", [])
        except (OSError, json.JSONDecodeError, AttributeError) as e:
            print(f"Error loading baseline file: {e}", file=sys.stderr)
            sys.exit(2)
    return config.get("baseline", [])

def _scan_stdin(args, exclude, skip_rules, only_rules, no_entropy, custom_rules):
    scanner = Scanner(
        ".", excludes=exclude, skip_rules=skip_rules, only_rules=only_rules,
        custom_rules=custom_rules,
    )
    scanner.include_entropy = not no_entropy
    text = sys.stdin.read()
    return scanner.scan_text(args.filename, text)


def _scan_staged(exclude, skip_rules, only_rules, custom_rules):
    files = staged_files()
    scanner = Scanner(
        ".", excludes=exclude, skip_rules=skip_rules, only_rules=only_rules,
        custom_rules=custom_rules,
    )
    findings = []
    for rel in files:
        candidate = os.path.relpath(rel, scanner.root).replace(os.sep, "/")
        if scanner._is_binary(candidate) or scanner._is_ignored(candidate):
            continue
        text = staged_content(rel)
        if text is None:
            continue
        findings.extend(scanner.scan_text(rel, text))
    return findings


def _scan_path(args, exclude, skip_rules, only_rules, no_entropy, custom_rules):
    scanner = Scanner(
        args.path, excludes=exclude, skip_rules=skip_rules, only_rules=only_rules,
        custom_rules=custom_rules,
    )
    scanner.include_entropy = not no_entropy
    return scanner.scan()


def _run_scan(args, exclude, skip_rules, only_rules, no_entropy, custom_rules):
    if args.stdin:
        return _scan_stdin(
            args, exclude, skip_rules, only_rules, no_entropy, custom_rules
        )
    if args.staged:
        return _scan_staged(exclude, skip_rules, only_rules, custom_rules)
    return _scan_path(
        args, exclude, skip_rules, only_rules, no_entropy, custom_rules
    )

def has_blocking_findings(findings, severity_threshold):
    """Return True if any finding meets or exceeds the severity threshold."""

    levels = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    threshold_val = levels.get(severity_threshold.lower(), 1)
    for f in findings:
        f_sev = f.get("severity", "medium").lower()
        if levels.get(f_sev, 2) >= threshold_val:
            return True
    return False


def _load_custom_rules(args, config, config_file):
    """Compile custom rules from config['rules'] and --rules-path.

    Both sources share one id namespace with the built-in rules, so a name
    that collides anywhere fails the scan. Any manifest problem is reported
    as a fatal configuration error (exit code 2) rather than ignored.
    """

    seen = {rid: "a built-in rule" for rid in known_rule_ids()}
    custom = []
    try:
        if "rules" in config:
            custom += compile_custom_rules(
                config["rules"], source=config_file, seen=seen
            )
        if getattr(args, "rules_path", None):
            custom += load_rules_file(args.rules_path, seen=seen)
    except RuleManifestError as exc:
        _config_fatal(f"Error: {exc}")
    return custom


def cmd_scan(args):
    scan_path = "." if args.staged else args.path
    config_file = find_config(scan_path)
    config = {}
    if config_file:
        config = load_config(config_file)

    # CLI flags override config values
    exclude = args.exclude if args.exclude else config.get("exclude", [])
    if args.skip_rule or args.only_rule:
        skip_rules = args.skip_rule
        only_rules = args.only_rule
    else:
        skip_rules = config.get("skip_rules", [])
        only_rules = config.get("only_rules", [])
    no_entropy = args.no_entropy or config.get("no_entropy", False)
    severity_threshold = getattr(args, "severity", None) or config.get(
        "severity", "low"
    )

    custom_rules = _load_custom_rules(args, config, config_file)

    unknown = unknown_rule_ids(skip_rules + only_rules, custom_rules)
    if unknown:
        print(
            "unknown rule id{}: {}".format(
                "s" if len(unknown) > 1 else "", ", ".join(unknown)
            ),
            file=sys.stderr,
        )
        print(
            "use --list-rules to see every available rule id", file=sys.stderr
        )
        return 2

    if args.list_rules:
        return list_rules(custom_rules)

    baseline = resolve_baseline(args, config)

    findings = _run_scan(
        args, exclude, skip_rules, only_rules, no_entropy, custom_rules
    )

    findings = filter_baseline(findings, baseline)

    max_findings = getattr(args, "max_findings", None)
    truncated = False
    shown = findings
    if max_findings is not None and len(findings) > max_findings:
        truncated = True
        shown = findings[:max_findings]

    if args.json:
        print(
            format_json(
                shown, os.path.abspath(args.path), show_value=args.show_value,
                truncated=truncated, total_findings=len(findings),
                reveal_prefix=args.reveal_prefix, reveal_suffix=args.reveal_suffix,
            )
        )
    else:
        color = False if args.no_color else None
        print(
            format_console(
                shown, args.path, show_value=args.show_value, color=color,
                truncated=truncated, total_findings=len(findings),
                reveal_prefix=args.reveal_prefix, reveal_suffix=args.reveal_suffix,
            )
        )
    return 1 if has_blocking_findings(findings, severity_threshold) else 0


def cmd_init(args):
    path = CONFIG_FILENAME
    if os.path.exists(path):
        print(
            f"Error: {path} already exists in the current directory.",
            file=sys.stderr,
        )
        return 1

    config_content = {
        "//": (
            "Secret-Guard Configuration File. Refer to "
            "https://github.com/taksh1507/secret-guard for details."
        ),
        "exclude": [],
        "no_entropy": False,
        "skip_rules": [],
        "only_rules": [],
        "rules": [],
    }

    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(config_content, f, indent=2)
            f.write("\n")
        print(f"Initialized starter configuration at {path}")
        return 0
    except OSError as e:
        print(f"Error writing starter configuration: {e}", file=sys.stderr)
        return 1


def cmd_install_hook(args):
    return install_hook()


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())