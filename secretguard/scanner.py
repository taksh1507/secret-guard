"""Filesystem scanning with gitignore-aware filtering."""

import concurrent.futures
import os

try:
    import pathspec

    HAS_PATHSPEC = True
except ImportError:  # pragma: no cover - optional dependency
    pathspec = None
    HAS_PATHSPEC = False

from .rules import (
    DOTENV_RULE_ID,
    ENTROPY_RULE_ID,
    RULES,
    dotenv_secret_assignments,
    entropy_candidates,
    is_dotenv_path,
    matches_rules,
)

BINARY_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".gz", ".tar",
    ".7z", ".exe", ".dll", ".so", ".dylib", ".bin", ".woff", ".woff2",
    ".ttf", ".eot", ".pyc", ".o", ".a", ".jar", ".class", ".sqlite",
    ".db", ".lock", ".min",
})

DEFAULT_EXCLUDES = frozenset({
    ".git", ".svn", ".hg", ".venv", "venv", "env", "node_modules",
    "dist", "build", "__pycache__", ".tox", ".nox", ".mypy_cache",
    ".pytest_cache", ".idea", ".vscode", "vendor", ".terraform",
})

# Cap on the auto-detected worker count. Per-file detection is already
# fast; beyond a modest number of processes, pool/IPC overhead outweighs
# the benefit for this workload, and this keeps a huge machine from
# oversubscribing itself for no real gain.
MAX_AUTO_WORKERS = 8

# A scan with fewer files than this isn't worth a process pool at all --
# starting one costs more than the sequential scan would take.
MIN_FILES_FOR_PARALLEL = 32

Finding = dict


class ScanConfig:
    """Picklable, self-contained rule configuration for a worker process.

    Deliberately holds nothing from Scanner beyond what detection itself
    needs -- not the gitignore matcher or root path. File selection (the
    gitignore/exclude/binary-extension checks) already happened on the
    main process before any work is handed to a worker; a worker only
    ever reads and scans the specific file it's given.
    """

    __slots__ = ("skip_rules", "only_rules", "custom_rules", "include_entropy")

    def __init__(self, skip_rules, only_rules, custom_rules, include_entropy):
        self.skip_rules = skip_rules
        self.only_rules = only_rules
        self.custom_rules = custom_rules
        self.include_entropy = include_entropy


def _rule_enabled(config, rule_id):
    if rule_id in config.skip_rules:
        return False
    if config.only_rules is not None and rule_id not in config.only_rules:
        return False
    if rule_id == ENTROPY_RULE_ID and not config.include_entropy:
        return False
    return True


def _scan_text_with_config(rel_path, text, config):
    """The actual detection pass, independent of any Scanner instance.

    Scanner.scan_text delegates here, and a parallel worker process (which
    has no Scanner instance at all -- only this picklable config) calls it
    directly, so both paths run exactly the same detection logic.
    """

    findings = []
    key_lines = set()
    if _rule_enabled(config, DOTENV_RULE_ID) and is_dotenv_path(rel_path):
        base = os.path.basename(rel_path)
        for line_no, key, _value in dotenv_secret_assignments(text):
            findings.append(
                _make_finding(
                    rel_path,
                    key,
                    {"name": "Environment File Secret", "id": DOTENV_RULE_ID},
                    "high",
                    line_no,
                    f"Assigned in a {base} file (value masked).",
                    reveal=True,
                )
            )
            key_lines.add(line_no)

    skip_rules = sorted(config.skip_rules)
    only_rules = sorted(config.only_rules) if config.only_rules else None
    rules = RULES + list(config.custom_rules)
    for rule, match in matches_rules(text, skip_rules, only_rules, rules):
        line = line_number(text, match.start())
        if line in key_lines:
            continue
        findings.append(
            _make_finding(
                rel_path,
                match.group(),
                {"name": rule["name"], "id": rule["id"]},
                rule["severity"],
                line,
                rule["description"],
            )
        )

    if _rule_enabled(config, ENTROPY_RULE_ID):
        for start, _end, entropy, value in entropy_candidates(text):
            line = line_number(text, start)
            if line in key_lines:
                continue
            findings.append(
                _make_finding(
                    rel_path,
                    value,
                    {"name": "High Entropy String", "id": ENTROPY_RULE_ID},
                    "low",
                    line,
                    f"Detected via Shannon entropy ({entropy:.2f} bits/char).",
                )
            )
    return findings


def _make_finding(path, value, rule_info, severity, line, description, reveal=False):
    finding = Finding(
        path=path,
        value=value,
        rule=rule_info["name"],
        rule_id=rule_info["id"],
        severity=severity,
        line=line,
        description=description,
    )
    if reveal:
        finding["reveal"] = True
    return finding


def _read_file(full_path):
    try:
        with open(full_path, encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except (OSError, PermissionError):
        return None


def _scan_file_worker(task):
    """Top-level, picklable entry point a ProcessPoolExecutor worker runs.

    Must stay a plain module-level function taking picklable arguments --
    a worker process has none of the calling Scanner's state except what's
    explicitly passed here.
    """

    full_path, rel_path, config = task
    text = _read_file(full_path)
    if text is None:
        return []
    return _scan_text_with_config(rel_path, text, config)


def _finding_sort_key(finding):
    return (finding["path"], finding["line"], finding["rule_id"], finding["value"])


class Scanner:
    def __init__(
        self,
        root,
        excludes=None,
        include_entropy=True,
        skip_rules=None,
        only_rules=None,
        custom_rules=None,
        workers=None,
    ):
        self.root = os.path.abspath(root)
        self.extra_excludes = set(excludes or [])
        self.include_entropy = include_entropy
        self.skip_rules = set(skip_rules or [])
        self.only_rules = set(only_rules or []) or None
        self.custom_rules = list(custom_rules or [])
        # None = auto-detect a worker count from the CPU count (capped),
        # only used once a scan actually has enough files to benefit; an
        # explicit 1 always forces the plain sequential path.
        self.workers = workers
        self._exclusions = DEFAULT_EXCLUDES | self.extra_excludes
        self._spec = None
        self._load_gitignore()

    def _load_gitignore(self):
        """Build a pathspec matcher from .gitignore, if available."""

        gitignore = os.path.join(self.root, ".gitignore")
        if not HAS_PATHSPEC or not os.path.isfile(gitignore):
            return
        with open(gitignore, encoding="utf-8", errors="replace") as handle:
            self._spec = pathspec.PathSpec.from_lines(
                "gitignore", handle.read().splitlines()
            )

    def _is_ignored(self, rel_path):
        if self._spec is not None and self._spec.match_file(rel_path):
            return True
        parts = rel_path.replace(os.sep, "/").split("/")
        for part in parts:
            if part in self._exclusions:
                return True
        return False

    def _is_binary(self, rel_path):
        for ext in BINARY_EXTENSIONS:
            if rel_path.lower().endswith(ext):
                return True
        return False

    def iter_files(self):
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = [
                d
                for d in dirnames
                if not self._is_ignored(os.path.join(dirpath, d))
            ]
            for filename in filenames:
                full = os.path.join(dirpath, filename)
                rel = os.path.relpath(full, self.root).replace(os.sep, "/")
                if self._is_ignored(rel):
                    continue
                if self._is_binary(rel):
                    continue
                yield full, rel

    def _config(self):
        return ScanConfig(
            skip_rules=frozenset(self.skip_rules),
            only_rules=(
                frozenset(self.only_rules) if self.only_rules is not None else None
            ),
            custom_rules=tuple(self.custom_rules),
            include_entropy=self.include_entropy,
        )

    def _resolve_workers(self, file_count):
        """How many worker processes this scan should use."""

        if self.workers is not None:
            return max(1, self.workers)
        if file_count < MIN_FILES_FOR_PARALLEL:
            return 1
        return max(1, min(os.cpu_count() or 1, MAX_AUTO_WORKERS))

    def scan(self):
        files = list(self.iter_files())
        worker_count = self._resolve_workers(len(files))

        if worker_count > 1:
            try:
                findings = self._scan_parallel(files, worker_count)
            except Exception:
                # A platform/sandbox that restricts process creation, an
                # unpicklable custom rule, or any other multiprocessing
                # surprise falls back to the plain sequential scan rather
                # than losing the scan entirely.
                findings = self._scan_sequential(files)
        else:
            findings = self._scan_sequential(files)

        # Sorted so output is identical regardless of whether it ran
        # sequentially or in parallel, and regardless of worker completion
        # order.
        findings.sort(key=_finding_sort_key)
        return findings

    def _scan_sequential(self, files):
        findings = []
        for full_path, rel_path in files:
            text = _read_file(full_path)
            if text is None:
                continue
            findings.extend(self.scan_text(rel_path, text))
        return findings

    def _scan_parallel(self, files, worker_count):
        config = self._config()
        tasks = [(full, rel, config) for full, rel in files]
        findings = []
        with concurrent.futures.ProcessPoolExecutor(max_workers=worker_count) as pool:
            for file_findings in pool.map(_scan_file_worker, tasks):
                findings.extend(file_findings)
        return findings

    def _rule_enabled(self, rule_id, include_entropy=None):
        """Whether a rule id should run given --skip-rule / --only-rule.

        `include_entropy` is the --no-entropy flag (None means use the stored
        include_entropy value); it only gates the entropy heuristic.
        """

        if rule_id in self.skip_rules:
            return False
        if self.only_rules is not None and rule_id not in self.only_rules:
            return False
        if rule_id == ENTROPY_RULE_ID:
            enabled = (
                self.include_entropy if include_entropy is None else include_entropy
            )
            if not enabled:
                return False
        return True

    def scan_text(self, rel_path, text):
        """Scan a single text blob for secrets (used by scan and staged scans).

        Dotenv files are special-cased: secret-looking key assignments are
        reported by key name only, so the underlying value is never echoed.
        """

        return _scan_text_with_config(rel_path, text, self._config())


def line_number(text, index):
    return text.count("\n", 0, index) + 1
