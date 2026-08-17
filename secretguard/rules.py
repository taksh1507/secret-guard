"""Detection rules: regex patterns and entropy heuristics."""

import math
import re

Rule = dict

# Rule ids used by --skip-rule / --only-rule for the rules that are not
# regex-based (and so live outside RULES).
ENTROPY_RULE_ID = "entropy"
DOTENV_RULE_ID = "dotenv"
SPECIAL_RULE_IDS = (ENTROPY_RULE_ID, DOTENV_RULE_ID)

SPECIAL_RULES = {
    ENTROPY_RULE_ID: {
        "id": ENTROPY_RULE_ID,
        "name": "High Entropy String",
        "severity": "low",
        "description": "Shannon-entropy heuristic for high-entropy strings.",
    },
    DOTENV_RULE_ID: {
        "id": DOTENV_RULE_ID,
        "name": "Environment File Secret",
        "severity": "high",
        "description": ".env file secret key assignment (value masked).",
    },
}


def _slugify(name):
    """Turn a rule name into a stable, CLI-friendly rule id."""

    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def _r(pattern, name, severity="medium", description=""):
    return {
        "id": _slugify(name),
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
        r"npm_[a-z0-9]{36}",
        "npm Token",
        severity="high",
        description="npm registry access token.",
    ),
    _r(
        r"SG\.[a-z0-9_-]{22}\.[a-z0-9_-]{43}",
        "SendGrid API Key",
        severity="high",
        description="SendGrid API key.",
    ),
    _r(
        r"SK[a-f0-9]{32}",
        "Twilio API Key",
        severity="high",
        description="Twilio API key SID.",
    ),
    _r(
        r"(?i)heroku[a-z0-9_.\-\t ]{0,30}(?:=|>|:=|\|\|:|<=|=>|:|\s)\s*"
        r"['\"]?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['\"]?",
        "Heroku API Key",
        severity="high",
        description="Heroku API key or authorization token.",
    ),
    _r(
        r"do[oprt]_v1_[a-f0-9]{64}",
        "DigitalOcean Token",
        severity="high",
        description="DigitalOcean personal access or OAuth token.",
    ),
    _r(
        r"pat-[a-z0-9-]{32,}",
        "HubSpot Access Token",
        severity="high",
        description="HubSpot Private App Access Token.",
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


def known_rule_ids():
    """Return every rule id the scanner can run in a scan."""

    return [rule["id"] for rule in RULES] + list(SPECIAL_RULE_IDS)


def unknown_rule_ids(rule_ids):
    """Return the rule ids supplied on the CLI that do not exist."""

    known = set(known_rule_ids())
    return sorted({rule_id for rule_id in rule_ids if rule_id not in known})


def matches_rules(text, skip_rules=None, only_rules=None):
    """Run regex rules against text, honoring rule-id filters.

    Only runs the intersection of `only_rules` (when given) with everything
    except `skip_rules`. Yields findings as (rule, match).
    """

    skips = set(skip_rules or ())
    if only_rules:
        enabled = [
            rule
            for rule in RULES
            if rule["id"] in only_rules and rule["id"] not in skips
        ]
    else:
        enabled = [rule for rule in RULES if rule["id"] not in skips]
    for rule in enabled:
        for match in rule["pattern"].finditer(text):
            yield rule, match


# Dotenv (.env) support: flag files that assign values to secret-looking keys,
# reporting the key name without ever exposing the assigned value.
#
# Supports the common dotenv subset: an optional `export` prefix, single-
# or double-quoted values (with backslash escapes for the quote character),
# and a trailing `# comment` on unquoted values. Variable interpolation
# (`$VAR` / `${VAR}`) is kept as opaque text and never resolved — resolving
# it would mean reading other variables' real values, which this scanner
# intentionally never does.
#
# Multiline quoted values are not supported: a value always ends at the
# line's newline, matching this parser's documented scope (not full
# python-dotenv semantics).
DOTENV_LINE = re.compile(
    r"^(?:export\s+)?(?P<key>[A-Za-z_][A-Za-z0-9_.]*)\s*=\s*(?P<rest>.*)$",
    re.IGNORECASE,
)
DOTENV_COMMENT_RE = re.compile(r"(?:^|\s)#")

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


def _parse_dotenv_value(rest):
    """Parse the right-hand side of a KEY=... line into a value string.

    Strips an optional surrounding quote (handling escaped quote/backslash
    characters) and any trailing inline `# comment` on unquoted values.
    Returns "" for a genuinely empty value.
    """
    rest = rest.strip()
    if not rest:
        return ""

    quote = rest[0]
    if quote in ("'", '"'):
        chars = []
        i = 1
        while i < len(rest):
            c = rest[i]
            if c == "\\" and i + 1 < len(rest) and rest[i + 1] in (quote, "\\"):
                chars.append(rest[i + 1])
                i += 2
                continue
            if c == quote:
                # Closing quote: anything after this is comment/whitespace,
                # never part of the value.
                return "".join(chars)
            chars.append(c)
            i += 1
        # No closing quote — malformed line; best-effort value.
        return "".join(chars)

    # Unquoted: an inline comment starts at a '#' preceded by whitespace or
    # at position 0, so a literal '#' inside a value like `p#ss=1` is kept.
    match = DOTENV_COMMENT_RE.search(rest)
    if match:
        rest = rest[: match.start()]
    return rest.strip()


def dotenv_secret_assignments(text):
    """Yield (line, key, value) for .env lines whose key names a secret."""

    for line_no, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = DOTENV_LINE.match(line)
        if not match:
            continue
        key = match.group("key")
        value = _parse_dotenv_value(match.group("rest"))
        if value and SECRET_KEY_PATTERN.search(key):
            yield line_no, key, value