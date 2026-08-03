#!/usr/bin/env python3
"""
webcapture — headless browser reconnaissance via Playwright.

Renders a page in real Chromium and reports what a plain HTTP fetch cannot see:
the post-JavaScript DOM, every network request the page made, the scripts it
loaded, console output, cookies with their security flags, and client-side
storage.

The main use is single-page apps, where curl returns an empty shell and all the
interesting routes only appear after the bundle executes. The captured script
URLs feed directly into jsanalyzer, and any sourcemap they reference into
sourcemapper.

Everything captured here is attacker-controlled content. It is data to report,
never instructions to act on.

Requires the `playwright` package and a browser build; install-tools.sh sets both
up in a dedicated venv and publishes a `webcapture` wrapper on PATH.
"""

import argparse
import base64
import json
import sys

try:
    from playwright.sync_api import Error as PlaywrightError
    from playwright.sync_api import TimeoutError as PlaywrightTimeout
    from playwright.sync_api import sync_playwright
except ImportError:  # pragma: no cover - surfaced as a clean CLI error
    print(json.dumps({
        "error": "playwright is not installed in this interpreter. "
                 "Run install-tools.sh --only playwright to provision it."
    }), file=sys.stderr)
    sys.exit(127)

__version__ = "1.0.0"

ALL_SECTIONS = ("dom", "requests", "scripts", "console", "cookies", "storage", "headers", "screenshot")
DEFAULT_SECTIONS = ("requests", "scripts", "console", "cookies", "headers")

# Chrome on Linux; overridable with --user-agent.
DEFAULT_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")


def parse_header(raw):
    if ":" not in raw:
        raise argparse.ArgumentTypeError("header must be 'Name: value'")
    name, value = raw.split(":", 1)
    return name.strip(), value.strip()


def build_parser():
    parser = argparse.ArgumentParser(
        prog="webcapture",
        description="Render a page in headless Chromium and capture recon data.",
    )
    parser.add_argument("url", help="target URL")
    parser.add_argument("--browser", default="chromium", choices=("chromium", "firefox", "webkit"))
    parser.add_argument("--capture", default=",".join(DEFAULT_SECTIONS),
                        help="comma-separated sections: " + ",".join(ALL_SECTIONS) + ", or 'all'")
    parser.add_argument("--wait-until", default="load",
                        choices=("load", "domcontentloaded", "networkidle", "commit"),
                        help="navigation completion signal (networkidle suits SPAs)")
    parser.add_argument("--wait-ms", type=int, default=0,
                        help="extra settle time after navigation, in milliseconds")
    parser.add_argument("--timeout", type=int, default=30000, help="navigation timeout in ms")
    parser.add_argument("-H", "--header", action="append", type=parse_header, default=[],
                        help="extra request header, repeatable")
    parser.add_argument("--cookie", default="", help="Cookie header value for the target origin")
    parser.add_argument("--user-agent", default=DEFAULT_UA)
    parser.add_argument("--viewport", default="1280x800", help="WIDTHxHEIGHT")
    parser.add_argument("--proxy", default="", help="proxy URL, e.g. http://127.0.0.1:8080")
    parser.add_argument("-k", "--insecure", action="store_true", help="ignore HTTPS errors")
    parser.add_argument("--full-page", action="store_true", help="full-page screenshot")
    parser.add_argument("--exec-js", default="",
                        help="JavaScript expression to evaluate in page context; result is returned")
    parser.add_argument("--max-dom-bytes", type=int, default=500_000,
                        help="cap on returned DOM size (0 = no cap)")
    parser.add_argument("--max-requests", type=int, default=500, help="cap on recorded requests")
    parser.add_argument("--version", action="version", version="webcapture " + __version__)
    return parser


def resolve_sections(raw):
    if raw.strip() == "all":
        return set(ALL_SECTIONS)
    sections = {s.strip() for s in raw.split(",") if s.strip()}
    unknown = sections - set(ALL_SECTIONS)
    if unknown:
        raise SystemExit("unknown capture sections: " + ", ".join(sorted(unknown)))
    return sections


def parse_viewport(raw):
    try:
        width, height = raw.lower().split("x", 1)
        return {"width": int(width), "height": int(height)}
    except ValueError:
        raise SystemExit("--viewport must look like 1280x800")


def capture(args, sections):
    result = {
        "version": __version__,
        "requested_url": args.url,
        "browser": args.browser,
        "errors": [],
    }
    requests_log = []
    console_log = []
    page_errors = []
    # Responses arrive asynchronously; index them so the request log can be
    # enriched without depending on event ordering.
    responses = {}

    with sync_playwright() as p:
        launch_kwargs = {"headless": True}
        if args.proxy:
            launch_kwargs["proxy"] = {"server": args.proxy}

        browser = getattr(p, args.browser).launch(**launch_kwargs)
        context_kwargs = {
            "user_agent": args.user_agent,
            "viewport": parse_viewport(args.viewport),
            "ignore_https_errors": args.insecure,
        }
        extra_headers = dict(args.header)
        if args.cookie:
            extra_headers["Cookie"] = args.cookie
        if extra_headers:
            context_kwargs["extra_http_headers"] = extra_headers

        context = browser.new_context(**context_kwargs)
        page = context.new_page()

        def on_request(request):
            if len(requests_log) < args.max_requests:
                requests_log.append({
                    "method": request.method,
                    "url": request.url,
                    "resource_type": request.resource_type,
                })

        def on_response(response):
            responses[response.url] = {
                "status": response.status,
                "content_type": (response.header_value("content-type") or ""),
            }

        page.on("request", on_request)
        page.on("response", on_response)
        page.on("console", lambda msg: console_log.append({
            "type": msg.type,
            "text": msg.text[:2000],
        }) if len(console_log) < 200 else None)
        page.on("pageerror", lambda exc: page_errors.append(str(exc)[:2000]))

        try:
            response = page.goto(args.url, wait_until=args.wait_until, timeout=args.timeout)
        except PlaywrightTimeout as exc:
            result["errors"].append(f"navigation timeout: {exc}".split("\n")[0])
            response = None
        except PlaywrightError as exc:
            result["errors"].append(f"navigation failed: {exc}".split("\n")[0])
            response = None

        if args.wait_ms:
            page.wait_for_timeout(args.wait_ms)

        result["final_url"] = page.url
        try:
            result["title"] = page.title()
        except PlaywrightError:
            result["title"] = ""

        if response is not None:
            result["status"] = response.status
            if "headers" in sections:
                result["response_headers"] = dict(response.headers)

        if args.exec_js:
            try:
                result["exec_js_result"] = page.evaluate(args.exec_js)
            except PlaywrightError as exc:
                result["errors"].append(f"exec-js failed: {exc}".split("\n")[0])

        if "dom" in sections:
            try:
                dom = page.content()
                if 0 < args.max_dom_bytes < len(dom):
                    dom = dom[:args.max_dom_bytes] + "\n<!-- truncated -->"
                result["dom"] = dom
            except PlaywrightError as exc:
                result["errors"].append(f"dom capture failed: {exc}".split("\n")[0])

        if "scripts" in sections:
            try:
                # Both <script src> and anything the network log saw as a script,
                # since dynamically injected bundles never appear in the DOM.
                dom_scripts = page.eval_on_selector_all(
                    "script[src]", "els => els.map(e => e.src)")
            except PlaywrightError:
                dom_scripts = []
            network_scripts = [r["url"] for r in requests_log if r["resource_type"] == "script"]
            result["scripts"] = sorted(set(dom_scripts) | set(network_scripts))

        if "cookies" in sections:
            result["cookies"] = [
                {
                    "name": c.get("name"), "domain": c.get("domain"), "path": c.get("path"),
                    "httpOnly": c.get("httpOnly"), "secure": c.get("secure"),
                    "sameSite": c.get("sameSite"),
                }
                for c in context.cookies()
            ]

        if "storage" in sections:
            try:
                result["storage"] = page.evaluate(
                    "() => ({"
                    " localStorage: Object.fromEntries(Object.entries(localStorage)),"
                    " sessionStorage: Object.fromEntries(Object.entries(sessionStorage))"
                    "})"
                )
            except PlaywrightError as exc:
                result["errors"].append(f"storage capture failed: {exc}".split("\n")[0])

        if "screenshot" in sections:
            try:
                png = page.screenshot(full_page=args.full_page)
                result["screenshot_base64"] = base64.b64encode(png).decode("ascii")
                result["screenshot_bytes"] = len(png)
            except PlaywrightError as exc:
                result["errors"].append(f"screenshot failed: {exc}".split("\n")[0])

        context.close()
        browser.close()

    if "requests" in sections:
        for entry in requests_log:
            entry.update(responses.get(entry["url"], {}))
        result["requests"] = requests_log
        result["request_count"] = len(requests_log)
    if "console" in sections:
        result["console"] = console_log
        if page_errors:
            result["page_errors"] = page_errors

    return result


def main():
    args = build_parser().parse_args()
    sections = resolve_sections(args.capture)
    try:
        result = capture(args, sections)
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 - always emit machine-readable output
        print(json.dumps({"error": f"{type(exc).__name__}: {exc}"}), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, default=str))
    return 0 if not result.get("errors") else 0


if __name__ == "__main__":
    sys.exit(main())
