"""Command-line interface for secret-guard."""

import argparse
import json
import os
import subprocess
import hashlib
import sys


from . import __version__
from .reporter import format_console, format_json
from .rules import RULES, SPECIAL_RULES, unknown_rule_ids
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
        config_file = os.path.join(curr, "secret-guard.json")
        if os.path.isfile(config_file):
            return config_file
        parent = os.path.dirname(curr)
        if parent == curr:
            break
        curr = parent
    return None


def load_config(config_path):
    """Load and validate secret-guard.json."""
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"Error parsing {config_path}: {e}", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(f"Error reading {config_path}: {e}", file=sys.stderr)
        sys.exit(2)
    
    if not isinstance(data, dict):
        print(f"Error: configuration root in {config_path} must be a JSON object.", file=sys.stderr)
        sys.exit(2)
        
    known_keys = {"exclude", "no_entropy", "skip_rules", "only_rules", "baseline", "//"}
    for key in data:
        if key not in known_keys:
            print(f"Warning: Unknown configuration key '{key}' in {config_path}", file=sys.stderr)
            
    if "exclude" in data:
        if not isinstance(data["exclude"], list) or not all(isinstance(x, str) for x in data["exclude"]):
            print(f"Error: 'exclude' in {config_path} must be a list of strings.", file=sys.stderr)
            sys.exit(2)
    if "no_entropy" in data:
        if not isinstance(data["no_entropy"], bool):
            print(f"Error: 'no_entropy' in {config_path} must be a boolean.", file=sys.stderr)
            sys.exit(2)
    if "skip_rules" in data:
        if not isinstance(data["skip_rules"], list) or not all(isinstance(x, str) for x in data["skip_rules"]):
            print(f"Error: 'skip_rules' in {config_path} must be a list of strings.", file=sys.stderr)
            sys.exit(2)
    if "only_rules" in data:
        if not isinstance(data["only_rules"], list) or not all(isinstance(x, str) for x in data["only_rules"]):
            print(f"Error: 'only_rules' in {config_path} must be a list of strings.", file=sys.stderr)
            sys.exit(2)
    if "baseline" in data:
        if not isinstance(data["baseline"], list) or not all(isinstance(x, dict) for x in data["baseline"]):
            print(f"Error: 'baseline' in {config_path} must be a list of objects.", file=sys.stderr)
            sys.exit(2)
            
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
        help="Print full secret values (default masks them).",
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
        "--skip-rule", action="append", default=[], metavar="RULE",
        help="Never run the given rule id (repeatable). Mixes with --only-rule.",
    )
    scan.add_argument(
        "--only-rule", action="append", default=[], metavar="RULE",
        help="Run only the given rule id (repeatable).",
    )
    scan.add_argument(
        "--list-rules", action="store_true",
        help="List every available rule id and exit.",
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


def list_rules():
    """Print every available rule id with name, severity, and description."""

    def fmt(info):
        return "  {:<30} {:<30} {:>8}  {}".format(
            info["id"], info["name"], info["severity"].upper(), info["description"]
)

    print("Regex rules:")
    for rule in RULES:
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

    unknown = unknown_rule_ids(skip_rules + only_rules)
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
        return list_rules()

    # Load baseline if provided via CLI or config file
    baseline = []
    if getattr(args, "baseline", None):
        try:
            with open(args.baseline, "r", encoding="utf-8") as f:
                baseline_data = json.load(f)
                baseline = baseline_data.get("baseline", [])
        except Exception as e:
            print(f"Error loading baseline file: {e}", file=sys.stderr)
            return 2
    else:
        baseline = config.get("baseline", [])

    if args.staged:
        files = staged_files()
        scanner = Scanner(
            ".",
            excludes=exclude,
            skip_rules=skip_rules,
            only_rules=only_rules,
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
    else:
        scanner = Scanner(
            args.path,
            excludes=exclude,
            skip_rules=skip_rules,
            only_rules=only_rules,
        )
        scanner.include_entropy = not no_entropy
        findings = scanner.scan()

    findings = filter_baseline(findings, baseline)

    if args.json:
        print(
            format_json(
                findings, os.path.abspath(args.path), show_value=args.show_value
            )
        )
    else:
        color = False if args.no_color else None
        print(
            format_console(
                findings, args.path, show_value=args.show_value, color=color
            )
        )
    return 1 if findings else 0


def cmd_init(args):
    path = "secret-guard.json"
    if os.path.exists(path):
        print(f"Error: {path} already exists in the current directory.", file=sys.stderr)
        return 1
        
    config_content = {
        "//": "Secret-Guard Configuration File. Refer to https://github.com/taksh1507/secret-guard for details.",
        "exclude": [],
        "no_entropy": False,
        "skip_rules": [],
        "only_rules": []
    }
    
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(config_content, f, indent=2)
            f.write("\n")
        print(f"Initialized starter configuration at {path}")
        return 0
    except Exception as e:
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