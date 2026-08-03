#!/usr/bin/env bash
#
# install-tools.sh — provision the tools exposed by the MCP Kali Server.
#
# Designed to run on the Kali host that serves server.py. Everything that can be
# installed without root goes to ~/.local (overridable with MKS_PREFIX), so the
# common case needs no password at all. Only the handful of tools that genuinely
# require distro packages ask for sudo, and they degrade to a warning instead of
# failing the run.
#
# Usage:
#   ./install-tools.sh                      # install everything that is missing
#   ./install-tools.sh --check              # report status, install nothing
#   ./install-tools.sh --only ffuf,nuclei   # install just these
#   ./install-tools.sh --skip ysoserial-net # install everything except these
#   ./install-tools.sh --force              # reinstall even if already present
#
set -euo pipefail

PREFIX="${MKS_PREFIX:-$HOME/.local}"
BIN_DIR="$PREFIX/bin"
OPT_DIR="$PREFIX/opt/mcp-kali"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

ALL_TOOLS=(sqlmap ffuf shcheck jsanalyzer sourcemapper trufflehog semgrep ysoserial ysoserial-net nuclei sslscan webcapture)
ONLY=""
SKIP=""
CHECK_ONLY=0
FORCE=0

# tool -> outcome, printed as a summary table at the end
declare -A RESULTS=()

# ---------------------------------------------------------------- ui helpers

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'
    C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_BLUE=$'\033[34m'
else
    C_RESET=""; C_BOLD=""; C_DIM=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""
fi

log()  { printf '%s[*]%s %s\n' "$C_BLUE"   "$C_RESET" "$*"; }
ok()   { printf '%s[+]%s %s\n' "$C_GREEN"  "$C_RESET" "$*"; }
warn() { printf '%s[!]%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
err()  { printf '%s[-]%s %s\n' "$C_RED"    "$C_RESET" "$*" >&2; }

usage() { sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

# --------------------------------------------------------------- arg parsing

while [ $# -gt 0 ]; do
    case "$1" in
        --check)  CHECK_ONLY=1; shift ;;
        --force)  FORCE=1; shift ;;
        --only)   ONLY="${2:-}"; shift 2 ;;
        --skip)   SKIP="${2:-}"; shift 2 ;;
        --prefix) PREFIX="${2:-}"; BIN_DIR="$PREFIX/bin"; OPT_DIR="$PREFIX/opt/mcp-kali"; shift 2 ;;
        -h|--help) usage ;;
        *) err "unknown option: $1"; usage ;;
    esac
done

# Does $1 appear in the comma-separated list $2?
in_list() {
    case ",$2," in *",$1,"*) return 0 ;; *) return 1 ;; esac
}

wanted() {
    local tool="$1"
    [ -n "$ONLY" ] && { in_list "$tool" "$ONLY" || return 1; }
    [ -n "$SKIP" ] && { in_list "$tool" "$SKIP" && return 1; }
    return 0
}

# ------------------------------------------------------------ system helpers

have() { command -v "$1" >/dev/null 2>&1; }

# Tools installed here land in ~/.local/bin and ~/go/bin, which are frequently
# absent from a non-login shell's PATH. Look there explicitly so --check and the
# idempotency guards agree with what server.py will later resolve.
installed() {
    local name="$1"
    have "$name" && return 0
    [ -x "$BIN_DIR/$name" ] && return 0
    [ -x "$(go env GOPATH 2>/dev/null)/bin/$name" ] && return 0
    return 1
}

# Run a command as root, but never block on a password prompt in a non-interactive
# run (the deploy path pipes this script over ssh). Returns non-zero when root is
# unavailable so callers can degrade instead of dying.
SUDO_UNAVAILABLE_WARNED=0
as_root() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    elif sudo -n true 2>/dev/null; then
        sudo "$@"
    elif [ -t 0 ]; then
        sudo "$@"
    else
        if [ "$SUDO_UNAVAILABLE_WARNED" -eq 0 ]; then
            warn "root privileges needed but this is a non-interactive shell; skipping apt steps"
            SUDO_UNAVAILABLE_WARNED=1
        fi
        return 1
    fi
}

arch_tag() {
    case "$(uname -m)" in
        x86_64|amd64) echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        armv7l) echo "arm" ;;
        *) echo "unsupported" ;;
    esac
}

# Latest release tag for a GitHub repo, without needing gh or a token.
latest_tag() {
    curl -fsSL "https://api.github.com/repos/$1/releases/latest" \
        | sed -n 's/.*"tag_name" *: *"\([^"]*\)".*/\1/p' | head -1
}

# Create a small exec wrapper in BIN_DIR so JVM/Mono tools behave like normal
# binaries on PATH.
write_wrapper() {
    local name="$1"; shift
    cat > "$BIN_DIR/$name" <<EOF
#!/usr/bin/env bash
exec $* "\$@"
EOF
    chmod +x "$BIN_DIR/$name"
}

need_cmd() {
    for c in "$@"; do
        have "$c" || { err "required command missing: $c"; return 1; }
    done
}

# ------------------------------------------------------------ tool installers

install_apt_tool() {
    # Tools that Kali already packages. Nothing to build, just make sure they exist.
    local tool="$1" pkg="${2:-$1}"
    if installed "$tool" && [ "$FORCE" -eq 0 ]; then
        RESULTS[$tool]="present  $(command -v "$tool" 2>/dev/null || echo "$BIN_DIR/$tool")"
        return 0
    fi
    log "installing $tool via apt ($pkg)"
    if as_root apt-get install -y "$pkg" >/dev/null 2>&1; then
        RESULTS[$tool]="installed $(command -v "$tool" 2>/dev/null || echo '')"
    else
        RESULTS[$tool]="MANUAL   run: sudo apt-get install -y $pkg"
        warn "$tool needs: sudo apt-get install -y $pkg"
    fi
}

install_pipx_tool() {
    local tool="$1" pkg="${2:-$1}" probe="${3:-$1}"
    if installed "$probe" && [ "$FORCE" -eq 0 ]; then
        RESULTS[$tool]="present  $(command -v "$probe" 2>/dev/null || echo "$BIN_DIR/$probe")"
        return 0
    fi
    have pipx || { RESULTS[$tool]="FAILED   pipx not installed"; err "pipx missing for $tool"; return 0; }
    log "installing $tool via pipx ($pkg)"
    local flags=(); [ "$FORCE" -eq 1 ] && flags+=(--force)
    if pipx install "${flags[@]}" "$pkg" >/dev/null 2>&1; then
        RESULTS[$tool]="installed $BIN_DIR/$probe"
    else
        # Surface the real reason rather than a bare failure.
        local out; out="$(pipx install "${flags[@]}" "$pkg" 2>&1 | tail -3 | tr '\n' ' ')"
        RESULTS[$tool]="FAILED   $out"
        err "$tool install failed: $out"
    fi
}

install_sqlmap()  { install_apt_tool sqlmap; }
install_ffuf()    { install_apt_tool ffuf; }
install_nuclei()  { install_apt_tool nuclei; }
install_sslscan() { install_apt_tool sslscan; }

install_shcheck() {
    # The PyPI package is `shcheck` but its console script keeps the upstream
    # name `shcheck.py`. On top of that, a prior `uv tool install` leaves a
    # ~/.local/bin/shcheck.py symlink that pipx will not overwrite, so pipx can
    # report success while nothing usable lands on PATH. Install into a known
    # venv and publish our own stable `shcheck` entry point.
    if installed shcheck && [ "$FORCE" -eq 0 ]; then
        RESULTS[shcheck]="present  $(command -v shcheck 2>/dev/null || echo "$BIN_DIR/shcheck")"
        return 0
    fi
    have pipx || { RESULTS[shcheck]="FAILED   pipx not installed"; err "pipx missing for shcheck"; return 0; }

    log "installing shcheck via pipx"
    if ! pipx install --force shcheck >/dev/null 2>&1; then
        local out; out="$(pipx install --force shcheck 2>&1 | tail -3 | tr '\n' ' ')"
        RESULTS[shcheck]="FAILED   $out"
        err "shcheck install failed: $out"
        return 0
    fi

    local script
    script="$(pipx environment --value PIPX_LOCAL_VENVS 2>/dev/null)/shcheck/bin/shcheck.py"
    [ -x "$script" ] || script="$HOME/.local/share/pipx/venvs/shcheck/bin/shcheck.py"
    if [ ! -x "$script" ]; then
        RESULTS[shcheck]="FAILED   pipx reported success but shcheck.py was not found"
        err "shcheck console script missing after install"
        return 0
    fi

    ln -sfn "$script" "$BIN_DIR/shcheck"
    RESULTS[shcheck]="installed $BIN_DIR/shcheck"
}

install_semgrep() {
    install_pipx_tool semgrep semgrep semgrep
}

install_jsanalyzer() {
    # Upstream JSAnalyzer is a Burp Suite extension (Jython + Swing), so there is
    # nothing to fetch. We ship a headless port in tools/jsanalyzer.py; this step
    # just publishes it on PATH so the API server resolves it like any other tool.
    local src
    src="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/tools/jsanalyzer.py"
    if [ ! -f "$src" ]; then
        RESULTS[jsanalyzer]="FAILED   tools/jsanalyzer.py not found next to this script"
        err "tools/jsanalyzer.py missing"
        return 0
    fi
    install -m 0755 "$src" "$BIN_DIR/jsanalyzer"
    RESULTS[jsanalyzer]="installed $BIN_DIR/jsanalyzer"
}

install_webcapture() {
    # Playwright needs a venv of its own rather than the distro package.
    # Debian/Kali ship python3-playwright as a "+ds" build with the bundled Node
    # driver stripped: it shells out to /usr/share/nodejs/playwright/cli.js from
    # the separate node-playwright package, which is pinned several major
    # versions behind (1.38 vs 1.55 at time of writing) and cannot drive it. A
    # PyPI install keeps the client and its driver in lockstep.
    local src venv
    src="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/tools/webcapture.py"
    venv="$OPT_DIR/playwright-venv"

    if [ ! -f "$src" ]; then
        RESULTS[webcapture]="FAILED   tools/webcapture.py not found next to this script"
        err "tools/webcapture.py missing"
        return 0
    fi

    if [ -x "$venv/bin/python" ] && "$venv/bin/python" -c "import playwright" 2>/dev/null && [ "$FORCE" -eq 0 ]; then
        log "playwright venv already present"
    else
        log "creating playwright venv (this downloads a browser build; several hundred MB)"
        rm -rf "$venv"
        if ! python3 -m venv "$venv" >/dev/null 2>&1; then
            RESULTS[webcapture]="FAILED   could not create venv (need python3-venv)"
            err "python3 -m venv failed; install python3-venv"
            return 0
        fi
        "$venv/bin/pip" install -q --upgrade pip >/dev/null 2>&1 || true
        if ! "$venv/bin/pip" install -q playwright >/dev/null 2>&1; then
            RESULTS[webcapture]="FAILED   pip install playwright failed"
            err "pip install playwright failed"
            return 0
        fi
        # Browsers land in ~/.cache/ms-playwright and are reused across venvs.
        if ! "$venv/bin/playwright" install chromium >/dev/null 2>&1; then
            RESULTS[webcapture]="PARTIAL  venv built but browser download failed; run: $venv/bin/playwright install chromium"
            warn "playwright browser download failed"
            install -m 0755 "$src" "$OPT_DIR/webcapture.py"
            write_wrapper webcapture "'$venv/bin/python' '$OPT_DIR/webcapture.py'"
            return 0
        fi
    fi

    install -m 0755 "$src" "$OPT_DIR/webcapture.py"
    write_wrapper webcapture "'$venv/bin/python' '$OPT_DIR/webcapture.py'"
    RESULTS[webcapture]="installed $BIN_DIR/webcapture"
}

install_sourcemapper() {
    if installed sourcemapper && [ "$FORCE" -eq 0 ]; then
        RESULTS[sourcemapper]="present  $(command -v sourcemapper 2>/dev/null || echo "$(go env GOPATH)/bin/sourcemapper")"
        return 0
    fi
    have go || { RESULTS[sourcemapper]="MANUAL   install golang, then: go install github.com/denandz/sourcemapper@latest"; warn "go missing for sourcemapper"; return 0; }
    log "installing sourcemapper via go install"
    if GOBIN="$BIN_DIR" go install github.com/denandz/sourcemapper@latest >/dev/null 2>&1; then
        RESULTS[sourcemapper]="installed $BIN_DIR/sourcemapper"
    else
        local out; out="$(GOBIN="$BIN_DIR" go install github.com/denandz/sourcemapper@latest 2>&1 | tail -2 | tr '\n' ' ')"
        RESULTS[sourcemapper]="FAILED   $out"
        err "sourcemapper install failed: $out"
    fi
}

install_trufflehog() {
    if installed trufflehog && [ "$FORCE" -eq 0 ]; then
        RESULTS[trufflehog]="present  $(command -v trufflehog 2>/dev/null || echo "$BIN_DIR/trufflehog")"
        return 0
    fi
    local arch tag ver url
    arch="$(arch_tag)"
    [ "$arch" = "unsupported" ] && { RESULTS[trufflehog]="FAILED   unsupported arch $(uname -m)"; return 0; }
    tag="$(latest_tag trufflesecurity/trufflehog)" || true
    [ -z "$tag" ] && { RESULTS[trufflehog]="FAILED   could not resolve latest release"; err "trufflehog: GitHub API lookup failed"; return 0; }
    ver="${tag#v}"
    url="https://github.com/trufflesecurity/trufflehog/releases/download/${tag}/trufflehog_${ver}_linux_${arch}.tar.gz"
    log "installing trufflehog $tag ($arch)"
    if curl -fsSL "$url" -o "$TMP_DIR/th.tar.gz" && tar -xzf "$TMP_DIR/th.tar.gz" -C "$TMP_DIR" trufflehog; then
        install -m 0755 "$TMP_DIR/trufflehog" "$BIN_DIR/trufflehog"
        RESULTS[trufflehog]="installed $BIN_DIR/trufflehog ($tag)"
    else
        RESULTS[trufflehog]="FAILED   download failed: $url"
        err "trufflehog download failed"
    fi
}

install_ysoserial() {
    # Java ysoserial: grab the fat jar and wrap it so `ysoserial` works on PATH.
    if installed ysoserial && [ "$FORCE" -eq 0 ]; then
        RESULTS[ysoserial]="present  $BIN_DIR/ysoserial"
        return 0
    fi
    have java || warn "java not found; ysoserial will install but cannot run until a JRE is present"
    local tag url dest="$OPT_DIR/ysoserial"
    tag="$(latest_tag frohoff/ysoserial)" || true
    [ -z "$tag" ] && tag="v0.0.6"
    url="https://github.com/frohoff/ysoserial/releases/download/${tag}/ysoserial-all.jar"
    log "installing ysoserial $tag"
    mkdir -p "$dest"
    if curl -fsSL "$url" -o "$dest/ysoserial-all.jar"; then
        # ysoserial predates JPMS. On any JDK 9+ its gadget chains die with
        # InaccessibleObjectException unless the relevant packages are opened to
        # the unnamed module, so the wrapper detects the runtime version and
        # applies --add-opens only where it is both needed and understood.
        cat > "$BIN_DIR/ysoserial" <<EOF
#!/usr/bin/env bash
JAR='$dest/ysoserial-all.jar'
major=\$(java -version 2>&1 | sed -n 's/.*version "\([0-9]*\).*/\1/p' | head -1)
OPENS=()
if [ -n "\$major" ] && [ "\$major" -ge 9 ] 2>/dev/null; then
    for pkg in java.util java.util.concurrent java.lang java.lang.reflect \\
               java.net java.io java.text java.math; do
        OPENS+=("--add-opens=java.base/\$pkg=ALL-UNNAMED")
    done
    OPENS+=("--add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED")
    OPENS+=("--add-opens=java.desktop/com.sun.beans.introspect=ALL-UNNAMED")
fi
exec java "\${OPENS[@]}" -jar "\$JAR" "\$@"
EOF
        chmod +x "$BIN_DIR/ysoserial"
        RESULTS[ysoserial]="installed $BIN_DIR/ysoserial ($tag)"
    else
        RESULTS[ysoserial]="FAILED   download failed: $url"
        err "ysoserial download failed"
    fi
}

install_ysoserial_net() {
    # ysoserial.net targets .NET Framework 4.7.2, so on Linux it runs under Mono.
    # The jar-equivalent here is a release zip containing ysoserial.exe.
    if installed ysoserial-net && [ "$FORCE" -eq 0 ]; then
        RESULTS[ysoserial-net]="present  $BIN_DIR/ysoserial-net"
        return 0
    fi
    local dest="$OPT_DIR/ysoserial.net"
    if ! have mono; then
        log "mono not present; attempting install (needed to run ysoserial.net)"
        if ! as_root apt-get install -y mono-runtime libmono-system-runtime4.0-cil >/dev/null 2>&1; then
            warn "could not install mono automatically"
        fi
    fi

    local tag url
    tag="$(latest_tag pwntester/ysoserial.net)" || true
    [ -z "$tag" ] && tag="v1.36"
    # Release asset names carry a commit hash, so discover it from the API.
    url="$(curl -fsSL "https://api.github.com/repos/pwntester/ysoserial.net/releases/tags/${tag}" \
        | sed -n 's/.*"browser_download_url" *: *"\([^"]*\.zip\)".*/\1/p' | head -1)"
    [ -z "$url" ] && { RESULTS[ysoserial-net]="FAILED   could not resolve release asset"; err "ysoserial.net asset lookup failed"; return 0; }

    log "installing ysoserial.net $tag"
    mkdir -p "$dest"
    if curl -fsSL "$url" -o "$TMP_DIR/yso.zip" && unzip -oq "$TMP_DIR/yso.zip" -d "$dest"; then
        local exe
        exe="$(find "$dest" -name 'ysoserial.exe' -print -quit)"
        if [ -z "$exe" ]; then
            RESULTS[ysoserial-net]="FAILED   ysoserial.exe not found in release zip"
            return 0
        fi
        write_wrapper ysoserial-net "mono '$exe'"
        if have mono; then
            RESULTS[ysoserial-net]="installed $BIN_DIR/ysoserial-net ($tag)"
        else
            RESULTS[ysoserial-net]="PARTIAL  installed, needs: sudo apt-get install -y mono-runtime libmono-system-runtime4.0-cil"
            warn "ysoserial.net installed but mono is missing; run: sudo apt-get install -y mono-runtime libmono-system-runtime4.0-cil"
        fi
    else
        RESULTS[ysoserial-net]="FAILED   download/unzip failed"
        err "ysoserial.net install failed"
    fi
}

# ------------------------------------------------------------------- reporting

print_summary() {
    local status_col
    printf '\n%s%-14s %s%s\n' "$C_BOLD" "TOOL" "STATUS" "$C_RESET"
    printf '%s%s%s\n' "$C_DIM" "$(printf '─%.0s' $(seq 1 68))" "$C_RESET"
    local failed=0 manual=0
    for tool in "${ALL_TOOLS[@]}"; do
        status_col="${RESULTS[$tool]:-skipped}"
        case "$status_col" in
            FAILED*)  printf '%-14s %s%s%s\n' "$tool" "$C_RED"    "$status_col" "$C_RESET"; failed=$((failed+1)) ;;
            MANUAL*|PARTIAL*) printf '%-14s %s%s%s\n' "$tool" "$C_YELLOW" "$status_col" "$C_RESET"; manual=$((manual+1)) ;;
            present*) printf '%-14s %s%s%s\n' "$tool" "$C_DIM"    "$status_col" "$C_RESET" ;;
            skipped)  printf '%-14s %s%s%s\n' "$tool" "$C_DIM"    "$status_col" "$C_RESET" ;;
            *)        printf '%-14s %s%s%s\n' "$tool" "$C_GREEN"  "$status_col" "$C_RESET" ;;
        esac
    done
    printf '%s%s%s\n' "$C_DIM" "$(printf '─%.0s' $(seq 1 68))" "$C_RESET"

    case ":$PATH:" in
        *":$BIN_DIR:"*) ;;
        *) warn "$BIN_DIR is not on PATH — add: export PATH=\"$BIN_DIR:\$PATH\"" ;;
    esac

    if [ "$failed" -gt 0 ]; then
        err "$failed tool(s) failed to install"
        return 1
    fi
    [ "$manual" -gt 0 ] && warn "$manual tool(s) need a manual step (see above)"
    ok "tool provisioning complete"
    return 0
}

# ------------------------------------------------------------------------ main

main() {
    need_cmd curl tar || exit 1
    mkdir -p "$BIN_DIR" "$OPT_DIR"

    log "prefix:  $PREFIX"
    log "arch:    $(uname -m) ($(arch_tag))"
    log "bin dir: $BIN_DIR"

    if [ "$CHECK_ONLY" -eq 1 ]; then
        for tool in "${ALL_TOOLS[@]}"; do
            if installed "$tool"; then
                RESULTS[$tool]="present  $(command -v "$tool" 2>/dev/null || echo "$BIN_DIR/$tool")"
            else
                RESULTS[$tool]="MANUAL   not installed"
            fi
        done
        print_summary
        return $?
    fi

    # apt indexes go stale on long-lived Kali VMs; refresh once if we can, and
    # only when an apt-backed tool is actually missing.
    local need_apt=0
    for t in sqlmap ffuf nuclei sslscan; do
        wanted "$t" && ! installed "$t" && need_apt=1
    done
    if [ "$need_apt" -eq 1 ]; then
        log "refreshing apt indexes"
        as_root apt-get update -qq >/dev/null 2>&1 || warn "apt-get update skipped"
    fi

    for tool in "${ALL_TOOLS[@]}"; do
        wanted "$tool" || continue
        case "$tool" in
            sqlmap)       install_sqlmap ;;
            ffuf)         install_ffuf ;;
            shcheck)      install_shcheck ;;
            jsanalyzer)   install_jsanalyzer ;;
            sourcemapper) install_sourcemapper ;;
            trufflehog)   install_trufflehog ;;
            semgrep)      install_semgrep ;;
            ysoserial)    install_ysoserial ;;
            ysoserial-net) install_ysoserial_net ;;
            nuclei)       install_nuclei ;;
            sslscan)      install_sslscan ;;
            webcapture)   install_webcapture ;;
        esac
    done

    print_summary
}

main "$@"
