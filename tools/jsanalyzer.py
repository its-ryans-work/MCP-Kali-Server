#!/usr/bin/env python3
"""
jsanalyzer — headless JavaScript static analysis.

Extracts API endpoints, URLs, secrets, emails and sensitive file references from
JavaScript, with aggressive noise filtering.

This is a headless port of JS Analyzer by Jensec (https://github.com/jenish-sojitra/JSAnalyzer),
which upstream is a Burp Suite extension built on Jython and Swing and therefore
cannot be shelled out to. The detection tables and filtering rules below are
derived from that project (MIT licensed); the CLI, fetching, confidence tiering
and output layer are new.

Differences from upstream, all deliberate:
  * Two upstream secret patterns match any 32-char hex/alphanumeric run, which in
    minified JS fires on every chunk hash. They are tagged low-confidence and are
    off unless --include-low-confidence is passed.
  * Findings keep the secret type label (upstream discards it in the UI path).
  * Secret values are shown in full by default because the operator needs them;
    --mask restores upstream's truncating behaviour.

Stdlib only, so it runs anywhere python3 does.
"""

import argparse
import concurrent.futures
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.request

__version__ = "1.0.0"

DEFAULT_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
MIN_BODY_LEN = 50

# ==================== ENDPOINT PATTERNS ====================

ENDPOINT_PATTERNS = [
    # API paths
    re.compile(r'["\']((?:https?:)?//[^"\']+/api/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE),
    re.compile(r'["\'](/api/v?\d*/[a-zA-Z0-9/_-]{2,})["\']', re.IGNORECASE),
    re.compile(r'["\'](/v\d+/[a-zA-Z0-9/_-]{2,})["\']', re.IGNORECASE),
    re.compile(r'["\'](/rest/[a-zA-Z0-9/_-]{2,})["\']', re.IGNORECASE),
    re.compile(r'["\'](/graphql[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    # Auth / identity
    re.compile(r'["\'](/oauth[0-9]*/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE),
    re.compile(r'["\'](/auth[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/login[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/logout[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/token[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    # Interesting surfaces
    re.compile(r'["\'](/admin[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/dashboard[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/internal[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/debug[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/config[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/backup[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/private[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/upload[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/download[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    # Well-known / IdP
    re.compile(r'["\'](/\.well-known/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE),
    re.compile(r'["\'](/idp/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE),
]

# ==================== URL PATTERNS ====================

URL_PATTERNS = [
    re.compile(r'["\'](https?://[^\s"\'<>]{10,})["\']'),
    re.compile(r'["\'](wss?://[^\s"\'<>]{10,})["\']'),
    re.compile(r'["\'](sftp://[^\s"\'<>]{10,})["\']'),
    # Cloud storage
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.s3[a-zA-Z0-9.-]*\.amazonaws\.com[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.blob\.core\.windows\.net[^\s"\'<>]*)'),
    re.compile(r'(https?://storage\.googleapis\.com/[^\s"\'<>]*)'),
    re.compile(r'(https://[a-z0-9-]+\.firebaseio\.com)'),
]

# ==================== SECRET PATTERNS ====================
# (regex, label, high_confidence)

SECRET_PATTERNS = [
    (re.compile(r'(AKIA[0-9A-Z]{16})'), "AWS Key", True),
    (re.compile(r'(AIza[0-9A-Za-z\-_]{35})'), "Google API", True),
    (re.compile(r'(sk_live_[0-9a-zA-Z]{24,})'), "Stripe Live", True),
    (re.compile(r'(ghp_[0-9a-zA-Z]{36})'), "GitHub PAT", True),
    (re.compile(r'(xox[baprs]-[0-9a-zA-Z\-]{10,48})'), "Slack Token", True),
    (re.compile(r'(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+)'), "JWT", True),
    (re.compile(r'(-----BEGIN (?:RSA |EC )?PRIVATE KEY-----)'), "Private Key", True),
    (re.compile(r'(mongodb(?:\+srv)?://[^\s"\'<>]+)'), "MongoDB", True),
    (re.compile(r'(postgres(?:ql)?://[^\s"\'<>]+)'), "PostgreSQL", True),
    (re.compile(r'(?i)algolia.{0,32}([a-z0-9]{32})\b'), "Algolia Admin API Key", True),
    (re.compile(r'(?i)algolia.{0,16}([A-Z0-9]{10})\b'), "Algolia Application ID", True),
    (re.compile(r'(?i)cloudflare.{0,32}(?:secret|private|access|key|token).{0,32}([a-z0-9_-]{38,42})\b'), "Cloudflare API Token", True),
    (re.compile(r'(?i)(?:cloudflare|x-auth-user-service-key).{0,64}(v1\.0-[a-z0-9._-]{160,})\b'), "Cloudflare Service Key", True),
    (re.compile(r'(mysql://[a-z0-9._%+\-]+:[^\s:@]+@(?:\[[0-9a-f:.]+\]|[a-z0-9.-]+)(?::\d{2,5})?(?:/[^\s"\'?:]+)?(?:\?[^\s"\']*)?)'), "MySQL URI with Credentials", True),
    (re.compile(r'\b(sgp_[A-Z0-9_-]{60,70})\b'), "Segment Public API Token", True),
    (re.compile(r'(?i)(?:segment|sgmt).{0,16}(?:secret|private|access|key|token).{0,16}([A-Z0-9_-]{40,50}\.[A-Z0-9_-]{40,50})'), "Segment API Key", True),
    (re.compile(r'(?i)(?:facebook|fb).{0,8}(?:app|application).{0,16}(\d{15})\b'), "Facebook App ID", True),
    (re.compile(r'(?i)(?:facebook|fb).{0,32}(?:api|app|application|client|consumer|secret|key).{0,32}([a-z0-9]{32})\b'), "Facebook Secret Key", True),
    (re.compile(r'(EAACEdEose0cBA[A-Z0-9]{20,})\b'), "Facebook Access Token", True),
    (re.compile(r'\b(ya29\.[a-z0-9_-]{30,})\b'), "Google OAuth2 Access Token", True),
    (re.compile(r'(\d{9}:[a-zA-Z0-9_-]{35})'), "Telegram Bot Token", True),
    (re.compile(r'(lin_api_[a-zA-Z0-9]{40})'), "Linear API Key", True),
    (re.compile(r"[hH]eroku['\"]([0-9a-f]{32})['\"]"), "Heroku API Key", True),
    (re.compile(r'(dop_v1_[a-z0-9]{64})'), "DigitalOcean Token", True),
    (re.compile(r'(SK[0-9a-fA-F]{32})'), "Twilio API Key", True),
    (re.compile(r'(SG\.[\w\d\-_]{22}\.[\w\d\-_]{43})'), "SendGrid API Key", True),
    (re.compile(r'(sl\.[A-Za-z0-9_-]{20,100})'), "Dropbox Access Token", True),
    (re.compile(r'(glpat-[0-9a-zA-Z\-_]{20})'), "GitLab Token", True),
    (re.compile(r'(shpat_[0-9a-fA-F]{32})'), "Shopify Access Token", True),
    (re.compile(r'(NRII-[a-zA-Z0-9]{20,})'), "New Relic Key", True),
    # Upstream keeps these unqualified; they match any 32-char hex/alnum run and
    # fire on every webpack chunk hash, so they are opt-in here.
    (re.compile(r'\b([a-f0-9]{32})\b'), "Bugsnag API Key (generic hex32)", False),
    (re.compile(r'\b([a-z0-9]{32})\b'), "Datadog API Key (generic alnum32)", False),
]

EMAIL_PATTERN = re.compile(r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6})')

FILE_PATTERNS = re.compile(
    r'["\']([a-zA-Z0-9_/.-]+\.(?:'
    r'sql|csv|xlsx|xls|json|xml|yaml|yml|'   # Data files
    r'txt|log|conf|config|cfg|ini|env|'      # Config/logs
    r'bak|backup|old|orig|copy|'             # Backups
    r'key|pem|crt|cer|p12|pfx|'              # Certificates
    r'doc|docx|pdf|'                         # Documents
    r'zip|tar|gz|rar|7z|'                    # Archives
    r'sh|bat|ps1|py|rb|pl'                   # Scripts
    r'))["\']',
    re.IGNORECASE,
)

# Source map comment, so callers can pivot straight into sourcemapper.
SOURCEMAP_PATTERN = re.compile(r'//[#@]\s*sourceMappingURL=([^\s*]+)')

# ==================== NOISE FILTERS ====================

NOISE_DOMAINS = {
    'www.w3.org', 'schemas.openxmlformats.org', 'schemas.microsoft.com',
    'purl.org', 'purl.oclc.org', 'openoffice.org', 'docs.oasis-open.org',
    'sheetjs.openxmlformats.org', 'ns.adobe.com', 'www.xml.org',
    'example.com', 'test.com', 'localhost', '127.0.0.1',
    'fusioncharts.com', 'jspdf.default.namespaceuri',
    'npmjs.org', 'registry.npmjs.org',
    'github.com/indutny', 'github.com/crypto-browserify',
    'jqwidgets.com', 'ag-grid.com',
}

NOISE_PATTERNS = [
    # Module/library imports
    re.compile(r'^\.\.?/'),
    re.compile(r'^[a-z]{2}(-[a-z]{2})?\.js$'),
    re.compile(r'^[a-z]{2}(-[a-z]{2})?$'),
    re.compile(r'-xform$'),
    re.compile(r'^sha\d*$'),
    re.compile(r'^aes$|^des$|^md5$'),
    # PDF internal structure
    re.compile(r'^/[A-Z][a-z]+\s'),
    re.compile(r'^/[A-Z][a-z]+$'),
    re.compile(r'^\d+ \d+ R$'),
    # Excel/XML internal paths
    re.compile(r'^xl/'),
    re.compile(r'^docProps/'),
    re.compile(r'^_rels/'),
    re.compile(r'^META-INF/'),
    re.compile(r'\.xml$'),
    re.compile(r'^worksheets/'),
    re.compile(r'^theme/'),
    # Build/bundler artifacts
    re.compile(r'^webpack'),
    re.compile(r'^zone\.js$'),
    re.compile(r'^readable-stream/'),
    re.compile(r'^process/'),
    re.compile(r'^stream/'),
    re.compile(r'^buffer$'),
    re.compile(r'^events$'),
    re.compile(r'^util$'),
    re.compile(r'^path$'),
    # Generic noise
    re.compile(r'^\+'),
    re.compile(r'^\$\{'),
    re.compile(r'^#'),
    re.compile(r'^\?\ref='),
    re.compile(r'^/[a-z]$'),
    re.compile(r'^/[A-Z]$'),
    re.compile(r'^http://$'),
    re.compile(r'_ngcontent'),
]

NOISE_STRINGS = {
    'http://', 'https://', '/a', '/P', '/R', '/V', '/W',
    'zone.js', 'bn.js', 'hash.js', 'md5.js', 'sha.js', 'des.js',
    'asn1.js', 'declare.js', 'elliptic.js',
}

STATIC_EXTENSIONS = ('.css', '.png', '.jpg', '.gif', '.svg', '.woff', '.ttf')
PLACEHOLDER_EMAIL_DOMAINS = {'example.com', 'test.com', 'domain.com', 'placeholder.com'}
NOISE_FILE_MARKERS = (
    'package.json', 'tsconfig.json', 'webpack', 'babel',
    'eslint', 'prettier', 'node_modules', '.min.',
    'polyfill', 'vendor', 'chunk', 'bundle',
)

# ==================== VALIDATION ====================


def is_valid_endpoint(value):
    if not value or len(value) < 3:
        return False
    if value in NOISE_STRINGS:
        return False
    for pattern in NOISE_PATTERNS:
        if pattern.search(value):
            return False
    if not value.startswith('/'):
        return False
    parts = value.split('/')
    if len(parts) < 2 or all(len(p) < 2 for p in parts if p):
        return False
    return True


def is_valid_url(value):
    if not value or len(value) < 15:
        return False
    lowered = value.lower()
    for domain in NOISE_DOMAINS:
        if domain in lowered:
            return False
    if '{' in value or 'undefined' in lowered or 'null' in lowered:
        return False
    if lowered.startswith('data:'):
        return False
    if lowered.endswith(STATIC_EXTENSIONS):
        return False
    return True


def is_valid_secret(value):
    if not value or len(value) < 10:
        return False
    lowered = value.lower()
    if any(x in lowered for x in ('example', 'placeholder', 'your', 'xxxx', 'test')):
        return False
    return True


def is_valid_email(value):
    if not value or '@' not in value:
        return False
    lowered = value.lower()
    if value.split('@')[-1].lower() in PLACEHOLDER_EMAIL_DOMAINS:
        return False
    if any(x in lowered for x in ('example', 'test', 'placeholder', 'noreply')):
        return False
    return True


def is_valid_file(value):
    if not value or len(value) < 3:
        return False
    lowered = value.lower()
    if any(x in lowered for x in NOISE_FILE_MARKERS):
        return False
    if lowered.endswith('.map'):
        return False
    # Locale bundles such as en.json / fr-CA.json
    if lowered.endswith('.json') and len(value.split('/')[-1]) <= 7:
        return False
    return True


# ==================== ANALYSIS ====================


def mask_secret(value):
    return value[:10] + "..." + value[-4:] if len(value) > 20 else value


class Analyzer:
    """Accumulates deduplicated findings across many sources."""

    def __init__(self, include_low_confidence=False, mask=False, categories=None):
        self.include_low_confidence = include_low_confidence
        self.mask = mask
        self.categories = categories or {
            "endpoints", "urls", "secrets", "emails", "files", "sourcemaps",
        }
        self.findings = []
        self._seen = set()

    def _add(self, category, value, source, secret_type=None, confidence=None):
        if category not in self.categories:
            return
        key = (category, value)
        if key in self._seen:
            return
        self._seen.add(key)
        finding = {"category": category, "value": value, "source": source}
        if secret_type:
            finding["type"] = secret_type
        if confidence:
            finding["confidence"] = confidence
        self.findings.append(finding)

    def analyze(self, body, source):
        """Run every detector over one JS body."""
        if not body or len(body) < MIN_BODY_LEN:
            return 0
        before = len(self.findings)

        for pattern in ENDPOINT_PATTERNS:
            for match in pattern.finditer(body):
                value = (match.group(1) or "").strip()
                if is_valid_endpoint(value):
                    self._add("endpoints", value, source)

        for pattern in URL_PATTERNS:
            for match in pattern.finditer(body):
                value = (match.group(1) if match.lastindex else match.group(0)).strip()
                if is_valid_url(value):
                    self._add("urls", value, source)

        for pattern, label, high_confidence in SECRET_PATTERNS:
            if not high_confidence and not self.include_low_confidence:
                continue
            for match in pattern.finditer(body):
                value = (match.group(1) if match.lastindex else match.group(0)).strip()
                if is_valid_secret(value):
                    self._add(
                        "secrets",
                        mask_secret(value) if self.mask else value,
                        source,
                        secret_type=label,
                        confidence="high" if high_confidence else "low",
                    )

        for match in EMAIL_PATTERN.finditer(body):
            value = match.group(1).strip()
            if is_valid_email(value):
                self._add("emails", value, source)

        for match in FILE_PATTERNS.finditer(body):
            value = match.group(1).strip()
            if is_valid_file(value):
                self._add("files", value, source)

        for match in SOURCEMAP_PATTERN.finditer(body):
            value = match.group(1).strip()
            if value and not value.startswith('data:'):
                self._add("sourcemaps", value, source)

        return len(self.findings) - before

    def grouped(self):
        out = {}
        for finding in self.findings:
            out.setdefault(finding["category"], []).append(finding)
        return out


# ==================== INPUT COLLECTION ====================


def fetch_url(url, timeout=20, insecure=False, headers=None, user_agent=DEFAULT_UA):
    request = urllib.request.Request(url, headers={"User-Agent": user_agent})
    for key, value in (headers or {}).items():
        request.add_header(key, value)
    context = None
    if insecure:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
        raw = response.read()
    return raw.decode("utf-8", errors="replace")


def read_file(path):
    with open(path, "rb") as handle:
        return handle.read().decode("utf-8", errors="replace")


def walk_dir(path, extensions):
    for root, _dirs, files in os.walk(path):
        for name in files:
            if name.lower().endswith(extensions):
                yield os.path.join(root, name)


def short_source(target):
    """Match upstream's compact source label."""
    if target.startswith(("http://", "https://")):
        name = target.split('/')[-1].split('?')[0] or target
    else:
        name = os.path.basename(target) or target
    return name[:40] + "..." if len(name) > 40 else name


# ==================== OUTPUT ====================


def render_text(analyzer, errors):
    lines = []
    grouped = analyzer.grouped()
    order = ["secrets", "endpoints", "urls", "sourcemaps", "files", "emails"]
    for category in order:
        items = grouped.get(category)
        if not items:
            continue
        lines.append("")
        lines.append("=== %s (%d) ===" % (category.upper(), len(items)))
        for finding in items:
            prefix = ""
            if finding.get("type"):
                prefix = "[%s] " % finding["type"]
            lines.append("  %s%s    (%s)" % (prefix, finding["value"], finding["source"]))
    if errors:
        lines.append("")
        lines.append("=== ERRORS (%d) ===" % len(errors))
        for error in errors:
            lines.append("  %s: %s" % (error["target"], error["error"]))
    if not analyzer.findings:
        lines.append("No findings.")
    return "\n".join(lines).lstrip("\n")


def parse_header(raw):
    if ":" not in raw:
        raise argparse.ArgumentTypeError("header must be 'Name: value'")
    name, value = raw.split(":", 1)
    return name.strip(), value.strip()


def main():
    parser = argparse.ArgumentParser(
        prog="jsanalyzer",
        description="Extract endpoints, URLs, secrets, emails and file references from JavaScript.",
        epilog="Detection rules derived from JS Analyzer by Jensec (github.com/jenish-sojitra/JSAnalyzer).",
    )
    parser.add_argument("targets", nargs="*", help="JS files, directories, or http(s) URLs")
    parser.add_argument("-l", "--list", help="file containing newline-separated targets")
    parser.add_argument("--json", action="store_true", help="emit JSON (default when not a TTY)")
    parser.add_argument("--text", action="store_true", help="force human-readable output")
    parser.add_argument("--categories", default="",
                        help="comma-separated subset of: endpoints,urls,secrets,emails,files,sourcemaps")
    parser.add_argument("--include-low-confidence", action="store_true",
                        help="enable generic 32-char hex/alnum secret patterns (very noisy)")
    parser.add_argument("--mask", action="store_true", help="truncate secret values in output")
    parser.add_argument("--timeout", type=int, default=20, help="per-URL fetch timeout (default: 20)")
    parser.add_argument("--threads", type=int, default=8, help="concurrent URL fetches (default: 8)")
    parser.add_argument("-k", "--insecure", action="store_true", help="skip TLS verification")
    parser.add_argument("-H", "--header", action="append", type=parse_header, default=[],
                        help="extra request header, repeatable (e.g. -H 'Cookie: a=b')")
    parser.add_argument("--user-agent", default=DEFAULT_UA)
    parser.add_argument("--ext", default=".js,.jsx,.ts,.tsx,.mjs,.cjs",
                        help="extensions to pick up when walking a directory")
    parser.add_argument("--version", action="version", version="jsanalyzer " + __version__)
    args = parser.parse_args()

    targets = list(args.targets)
    if args.list:
        try:
            with open(args.list) as handle:
                targets += [line.strip() for line in handle if line.strip()]
        except OSError as exc:
            print("error: cannot read --list file: %s" % exc, file=sys.stderr)
            return 2
    if not targets and not sys.stdin.isatty():
        targets += [line.strip() for line in sys.stdin if line.strip()]

    if not targets:
        parser.error("no targets given (pass files, directories, URLs, --list, or stdin)")

    categories = None
    if args.categories:
        categories = {c.strip() for c in args.categories.split(",") if c.strip()}
        valid = {"endpoints", "urls", "secrets", "emails", "files", "sourcemaps"}
        unknown = categories - valid
        if unknown:
            parser.error("unknown categories: %s" % ", ".join(sorted(unknown)))

    extensions = tuple(e.strip() for e in args.ext.split(",") if e.strip())

    # Expand directories, keep files and URLs as-is.
    expanded = []
    for target in targets:
        if target.startswith(("http://", "https://")):
            expanded.append(target)
        elif os.path.isdir(target):
            expanded.extend(walk_dir(target, extensions))
        else:
            expanded.append(target)

    analyzer = Analyzer(
        include_low_confidence=args.include_low_confidence,
        mask=args.mask,
        categories=categories,
    )
    errors = []
    headers = dict(args.header)

    urls = [t for t in expanded if t.startswith(("http://", "https://"))]
    paths = [t for t in expanded if not t.startswith(("http://", "https://"))]

    for path in paths:
        try:
            analyzer.analyze(read_file(path), short_source(path))
        except OSError as exc:
            errors.append({"target": path, "error": str(exc)})

    if urls:
        # Fetch concurrently; analysis itself stays on this thread so the
        # dedup set needs no locking.
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.threads)) as pool:
            futures = {
                pool.submit(fetch_url, url, args.timeout, args.insecure, headers, args.user_agent): url
                for url in urls
            }
            for future in concurrent.futures.as_completed(futures):
                url = futures[future]
                try:
                    analyzer.analyze(future.result(), short_source(url))
                except (urllib.error.URLError, OSError, ValueError) as exc:
                    errors.append({"target": url, "error": str(exc)})

    use_json = args.json or (not args.text and not sys.stdout.isatty())
    if use_json:
        payload = {
            "version": __version__,
            "sources_analyzed": len(expanded) - len(errors),
            "total_findings": len(analyzer.findings),
            "counts": {k: len(v) for k, v in analyzer.grouped().items()},
            "findings": analyzer.findings,
            "errors": errors,
        }
        print(json.dumps(payload, indent=2))
    else:
        print(render_text(analyzer, errors))

    # Non-zero only on total failure, so a clean "no findings" run stays green.
    if errors and not analyzer.findings:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
