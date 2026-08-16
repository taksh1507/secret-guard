"""Detection rules: regex patterns and entropy heuristics."""

import math
import re

Rule = dict


def _r(pattern, name, severity="medium", description=""):
    return {
        "name": name,
        "pattern": re.compile(pattern, re.MULTILINE | re.IGNORECASE),
        "severity": severity,
        "description": description,
    }


RULES = [
    _r(
        r"(?i)AKIA[0-9A-Z]{16}",
        "AWS Access Key ID",
        severity="high",
        description="Amazon Web Services access key identifier.",
    ),
    _r(
        r"(?i)(ASIA|AGPA|AIDA|ANPA)[0-9A-Z]{16}",
        "AWS Temporary/Assigned Key",
        severity="high",
        description="Amazon Web Services key identifier.",
    ),
    _r(
        r"gh[pousr]_[A-Za-z0-9_]{20,}",
        "GitHub Token",
        severity="high",
        description="GitHub Personal Access / OAuth token.",
    ),
    _r(
        r"github_pat_[A-Za-z0-9_]{22,}",
        "GitHub Fine-grained Token",
        severity="high",
        description="GitHub fine-grained personal access token.",
    ),
    _r(
        r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY( BLOCK)?-----",
        "Private Key",
        severity="critical",
        description="Private cryptographic key material.",
    ),
    _r(
        r"(?i)xox[baprs]-[0-9A-Za-z-]{10,}",
        "Slack Token",
        severity="high",
        description="Slack API bot/app/user token.",
    ),
    _r(
        r"AIza[0-9A-Za-z_-]{35}",
        "Google API Key",
        severity="high",
        description="Google Cloud / Maps API key.",
    ),
    _r(
        r"sk-live-[0-9A-Za-z_-]{20,}",
        "Stripe Secret Key",
        severity="high",
        description="Stripe live secret API key.",
    ),
    _r(
        r"sk-[0-9a-fA-F]{32,}",
        "Generic Secret Key",
        severity="medium",
        description="Suspicious application secret key.",
    ),
    _r(
        r"(?i)eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        "JWT Token",
        severity="high",
        description="JSON Web Token.",
    ),
    _r(
        r"(?i)sq0atp-[0-9A-Za-z_-]{22,}",
        "Square Access Token",
        severity="high",
        description="Square API access token.",
    ),
    _r(
        r"(?i)AKIA-[0-9A-Z]{16}",
        "AWS Key (dashed)",
        severity="high",
        description="Amazon Web Services key (dash separated).",
    ),
    _r(
        r"(?i)^(?:password|passwd|pwd|pass|secret|token|api[_-]?key|"
        r"access[_-]?key)\s*[:=][ \t]*['\"]?[^'\s]{6,}['\"]?$",
        "Credential Assignment",
        severity="medium",
        description="A variable named like a credential assigned a value.",
    ),
]

# Charsets used for entropy scoring.
HEX_CHARS = set("0123456789abcdefABCDEF")
BASE64_CHARS = set(
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_"
)

ALPHANUMERIC = re.compile(r"[A-Za-z0-9_-]{12,}")

_MIN_ENTROPY_LEN = 20
_HIGH_ENTROPY = 3.5


def shannon_entropy(data):
    """Compute Shannon entropy (bits per character) of a string."""

    if not data:
        return 0.0
    length = len(data)
    counts = {}
    for char in data:
        counts[char] = counts.get(char, 0) + 1
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


def entropy_candidates(text):
    """Yield (start, end, entropy, value) for high-entropy strings."""

    for match in ALPHANUMERIC.finditer(text):
        value = match.group()
        if len(value) < _MIN_ENTROPY_LEN:
            continue
        entropy = shannon_entropy(value)
        if entropy >= _HIGH_ENTROPY:
            yield match.start(), match.end(), entropy, value


def matches_rules(text):
    """Run all regex rules against text, yield findings as (rule, match)."""

    for rule in RULES:
        for match in rule["pattern"].finditer(text):
            yield rule, match


# Dotenv (.env) support: flag files that assign values to secret-looking keys,
# reporting the key name without ever exposing the assigned value.
DOTENV_LINE = re.compile(
    r"^(?P<key>[A-Za-z_][A-Za-z0-9_.]*)\s*=\s*(?P<value>.*)$"
)
SECRET_KEY_PATTERN = re.compile(
    r"(?i)(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|"
    r"private[_-]?key|credential|client[_-]?secret|consumer[_-]?secret|"
    r"session[_-]?secret|cookie[_-]?secret|auth[_-]?(secret|token|key)|"
    r"db[_-]?(password|passwd|pwd|secret))"
)


DOTENV_TEMPLATE_RE = re.compile(
    r"\.(?:example|sample|template|dist)(?:\.\w+)*$", re.IGNORECASE
)


def is_dotenv_path(rel_path):
    base = rel_path.rsplit("/", 1)[-1]
    if DOTENV_TEMPLATE_RE.search(base) and re.search(r"\.env", base, re.IGNORECASE):
        return False
    return bool(re.search(r"\.env(\.|$)", base, re.IGNORECASE))


def dotenv_secret_assignments(text):
    """Yield (line, key, value) for .env lines whose key names a secret."""

    for line_no, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = DOTENV_LINE.match(line)
        if not match:
            continue
        key = match.group("key")
        value = match.group("value").strip()
        if value and SECRET_KEY_PATTERN.search(key):
            yield line_no, key, value