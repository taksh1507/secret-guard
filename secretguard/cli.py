"""Command-line interface for secret-guard."""

import argparse
import os
import subprocess
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


def cmd_scan(args):
    unknown = unknown_rule_ids(args.skip_rule + args.only_rule)
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

    if args.staged:
        files = staged_files()
        scanner = Scanner(
            ".", excludes=args.exclude, skip_rules=args.skip_rule,
            only_rules=args.only_rule,
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
            args.path, excludes=args.exclude, skip_rules=args.skip_rule,
            only_rules=args.only_rule,
        )
        scanner.include_entropy = not args.no_entropy
        findings = scanner.scan()

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