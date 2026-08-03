# MCP Kali Server

**MCP Kali Server (MKS)** is a lightweight API bridge that connects [MCP clients](https://modelcontextprotocol.io/clients) (e.g: [Claude Desktop](https://code.claude.com/docs/en/desktop) or [5ire](https://github.com/nanbingxyz/5ire)) to the [API server](https://modelcontextprotocol.io/examples) which allows executing commands on a Linux terminal.

This MCP is able to run terminal commands as well as interacting with web applications using:

- `Dirb`
- `enum4linux`
- `gobuster`
- `Hydra`
- `John the Ripper`
- `Metasploit-Framework`
- `Nikto`
- `Nmap`
- `sqlmap`
- `WPScan`
- As well as being able to execute raw commands.

As a result, this is able to perform **AI-assisted penetration testing** and solving **CTF challenges** in real time.

> This is a fork of [Wh0am123/MCP-Kali-Server](https://github.com/Wh0am123/MCP-Kali-Server) that adds
> the web/appsec toolchain listed below, a provisioning script, and a deployment helper.

## 🧰 Added Tooling

This fork adds thirteen tools on top of upstream. Each has a dedicated API endpoint and MCP tool with
typed parameters, so the model does not have to build command lines by hand.

| Tool | MCP tool | What it covers |
|---|---|---|
| [SQLMap](https://github.com/sqlmapproject/sqlmap) | `sqlmap_scan` | SQL injection; upstream's endpoint extended with enumeration flags (`dbs`/`tables`/`columns`/`dump`), tamper scripts, level/risk and proxying |
| [ffuf](https://github.com/ffuf/ffuf) | `ffuf_fuzz` | Content, vhost and parameter fuzzing with the full matcher/filter set |
| [shcheck](https://github.com/santoru/shcheck) | `shcheck_headers` | HTTP security header presence and gaps |
| [JS Analyzer](https://github.com/jenish-sojitra/JSAnalyzer) | `js_analyze` | Endpoints, URLs, secrets, emails, file refs and sourcemap links in JavaScript |
| [sourcemapper](https://github.com/denandz/sourcemapper) | `sourcemapper_extract` | Recovers original source trees from `.js.map` files |
| [TruffleHog](https://github.com/trufflesecurity/trufflehog) | `trufflehog_scan` | Live-verified credential discovery across git, filesystem, S3, Docker and more |
| [Semgrep](https://github.com/semgrep/semgrep) | `semgrep_scan` | Static analysis with registry rulepacks or local rules |
| [ysoserial](https://github.com/frohoff/ysoserial) | `ysoserial_generate` | Java deserialization payloads |
| [ysoserial.net](https://github.com/pwntester/ysoserial.net) | `ysoserial_net_generate` | .NET deserialization payloads (gadget + formatter) |
| [Nuclei](https://github.com/projectdiscovery/nuclei) | `nuclei_scan` | Template-driven vulnerability scanning |
| [sslscan](https://github.com/rbsec/sslscan) | `sslscan_scan` | TLS versions, ciphers, certificates and known weaknesses |
| [Playwright](https://github.com/microsoft/playwright) | `web_capture` | Renders a page in real Chromium: post-JS DOM, network log, loaded scripts, console, cookie flags, storage, screenshot |
| [bangbang](https://github.com/its-ryans-work/bangbang) | `bangbang_search` | Finds a product's CVEs on NVD, then hunts GitHub/GitLab/Codeberg/exploit-db for public PoCs, and can clone them |

These chain naturally. A typical run on a single-page app:

```
web_capture (wait_until=networkidle)   -> discovers dynamically injected bundles that
                                          are absent from the served HTML
  -> js_analyze on those script URLs   -> endpoints, secrets, sourceMappingURL
  -> sourcemapper_extract              -> original pre-minification source tree
  -> semgrep_scan / trufflehog_scan    -> vulnerabilities and credentials in that source
```

`bangbang_search` covers the other direction — starting from a product or CVE rather than from a live
target. Group numbers in its output (`1`, `1.2`) feed its own `select` parameter to clone a PoC, which
`semgrep_scan` or `trufflehog_scan` can then read. Cloned PoC code is untrusted and is never executed.

### Notes on four of them

**JS Analyzer** is upstream a Burp Suite extension (Jython + Swing) with no CLI, so it cannot be shelled
out to. This fork ships a headless port at [`tools/jsanalyzer.py`](tools/jsanalyzer.py) that reuses its
detection tables and noise filters, and adds URL/directory input, JSON output and concurrent fetching.
Two upstream secret patterns match any 32-character hex or alphanumeric run — which fires on every
webpack chunk hash — so they are gated behind `include_low_confidence`.

**ysoserial payloads are binary**, not text: a Java payload begins with the bytes `AC ED 00 05` and is not
valid UTF-8. Both payload endpoints therefore return `stdout_base64` (with a `stdout_bytes` length)
rather than `stdout`. Decode before sending onward.

**bangbang is a REPL, driven here without one.** It prints results and then drops into an interactive
prompt. That suits an API better than it looks: its first-run auth wizard is TTY-gated, its REPL exits
on stdin EOF, and it drops ANSI colour when stdout is not a TTY — so with stdin at `/dev/null` a search
is already a clean one-shot command. Downloads reuse the same channel, feeding `select N` and
`download` on stdin. Because of that, the server now wires **every** tool's stdin to `/dev/null` by
default; any tool that unexpectedly prompts hits EOF instead of blocking until its timeout.

**Playwright is installed into its own venv**, not from apt. Kali packages `python3-playwright` as a `+ds`
build with the bundled Node driver removed — it expects `/usr/share/nodejs/playwright/cli.js` from the
separate `node-playwright` package, which is pinned several major versions behind (1.38 against 1.55) and
cannot drive it. `install-tools.sh` therefore builds a dedicated venv from PyPI so client and driver stay
in lockstep, and publishes a `webcapture` wrapper on `PATH`. Browser builds live in the shared
`~/.cache/ms-playwright` and are reused.

## 📦 Installing the tools

`install-tools.sh` provisions everything on the Kali host. It is idempotent, architecture-aware
(amd64/arm64), and installs to `~/.local` so the common case needs no root at all — only tools that must
come from apt will ask for sudo, and those degrade to a printed instruction rather than failing the run.

```bash
./install-tools.sh              # install whatever is missing
./install-tools.sh --check      # report status, change nothing
./install-tools.sh --only ffuf,nuclei
./install-tools.sh --skip ysoserial-net
./install-tools.sh --force      # reinstall even if present
```

`server.py` adds `~/.local/bin` and the Go bin directory to `PATH` at startup, so tools installed this way
resolve even when the server runs from systemd or a non-login shell. `GET /health` reports which of the
extended tools are actually usable — including runtime dependencies, so `ysoserial_net` reads as
unavailable when Mono is missing rather than merely because a wrapper script exists.

**ysoserial.net requires Mono**, which only apt can provide:

```bash
sudo apt-get install -y mono-runtime libmono-system-runtime4.0-cil
```

Mono runs ysoserial.net but does not make every gadget usable. Mono never implemented WPF, so gadgets
needing `PresentationCore` or `PresentationFramework` — `ObjectDataProvider`, `WindowsIdentity`,
`AxHostState`, `DataSet` — fail with a missing-assembly error on any Linux host, and plain
`TypeConfuseDelegate` throws a `NullReferenceException`, which is why the build ships a Mono variant.
Verified working here:

| Gadget | Formatters |
|---|---|
| `TypeConfuseDelegateMono` | `BinaryFormatter`, `LosFormatter`, `NetDataContractSerializer` |

Generating payloads for the WPF-backed gadgets needs Windows or .NET Framework.

## 🚀 Deploying to a remote Kali host

`deploy.sh.example` is a template for syncing this repo to a Kali box and managing the API server there.
Copy it to `deploy.local.sh` — which is gitignored, so your host address and SSH key path never reach the
repository — and fill in your own values:

```bash
cp deploy.sh.example deploy.local.sh
chmod +x deploy.local.sh
$EDITOR deploy.local.sh          # set KALI_HOST, KALI_USER, KALI_KEY
./deploy.local.sh install        # sync, then provision tools
./deploy.local.sh start          # start the API server
./deploy.local.sh status         # health check
```

> The default API port here is **5111**, not upstream's 5000. ASP.NET Core/Kestrel binds 5000 by default,
> so that port is frequently already taken on a developer machine.

## 🖥️ Desktop launcher

To start the server from the Kali desktop rather than a shell, run this **on the Kali host**:

```bash
./install-desktop-launcher.sh
```

It installs a control script to `~/.local/bin/mcp-kali-server` and a launcher to both the desktop and
the application menu (right-click it for **Show status** / **Stop server**). Paths are resolved at
install time, so nothing host-specific is committed. Remove it with `--uninstall`.

The control script works standalone too:

```bash
mcp-kali-server {start|stop|restart|status|logs}
```

`status` prints the pid and how many tools the health endpoint reports as usable. The server is
started with `setsid`, so it keeps running after the launching terminal closes — the window only
follows the log, and closing it does not stop the server.

Two details that matter on GNOME: a `.desktop` file dropped on the desktop shows as "Untrusted
application launcher" until `metadata::trusted` is set, which the installer does; and the entry lists
a single main category, because listing several makes it appear repeatedly in the application menu.

This is a login-time convenience, not a service manager — nothing here starts the server at boot. If
you want that, a user systemd unit with `WantedBy=default.target` is the better tool.

## Articles Using This Tool

[![How MCP is Revolutionizing Offensive Security](https://miro.medium.com/v2/resize:fit:828/format:webp/1*g4h-mIpPEHpq_H63W7Emsg.png)](https://yousofnahya.medium.com/how-mcp-is-revolutionizing-offensive-security-93b2442a5096)

👉 [**How MCP is Revolutionizing Offensive Security**](https://yousofnahya.medium.com/how-mcp-is-revolutionizing-offensive-security-93b2442a5096)

---

## 🔍 Use Case

The goal is to enable AI-driven offensive security testing by:

- Letting the MCP interact with AI endpoints like [OpenAI](https://openai.com/), [Claude](https://claude.ai/), [DeepSeek](https://www.deepseek.com/), [Ollama](https://docs.ollama.com/) or any other models.
- Exposing an API to execute commands on a [Kali](https://www.kali.org/) machine.
- Using AI to suggest and run terminal commands to [solve CTF challenges](#example-solving-a-web-ctf-challenge-from-ramadanctf) or automate recon/exploitation tasks.
- Allowing MCP apps to send custom requests (e.g. `curl`, `nmap`, `ffuf`, etc.) and receive structured outputs.

Here are some example (using Google's AI `gemini 2.0 flash`):

### Example solving a web CTF challenge from RamadanCTF

https://github.com/user-attachments/assets/dc93b71d-9a4a-4ad5-8079-2c26c04e5397

### Trying to solve machine "code" from HTB

https://github.com/user-attachments/assets/3ec06ff8-0bdf-4ad5-be71-2ec490b7ee27

---

## 🚀 Features

- 🧠 **AI Endpoint Integration**: Connect your Kali to any MCP of your liking such as Claude Desktop or 5ier.
- 🖥️ **Command Execution API**: Exposes a controlled API to execute terminal commands on your Kali Linux machine.
- 🕸️ **Web Challenge Support**: AI can interact with websites and APIs, capture flags via `curl` and any other tool AI the needs.
- 🔐 **Designed for Offensive Security Professionals**: Ideal for red teamers, bug bounty hunters, or CTF players automating common tasks.

---

## 🛠️ Installation and Running

### On your Kali Machine

```bash
sudo apt install mcp-kali-server
kali-server-mcp
```

Otherwise for **bleeding edge**:

```bash
git clone https://github.com/Wh0am123/MCP-Kali-Server.git
cd MCP-Kali-Server
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
./server.py
```

**Command Line Options**:

- `--ip <address>`: Specify the IP address to bind the server to (default: `127.0.0.1` for localhost only)
  - Use `127.0.0.1` for local connections only (secure, recommended)
  - Use `0.0.0.0` to allow connections from any network interface (very dangerous; use with caution)
  - Use a specific IP address to bind to a particular network interface
- `--port <port>`: Specify the port number (default: `5000`)
- `--debug`: Enable debug mode for verbose logging

**Examples**:

```bash
# Run on localhost only (secure, default)
./server.py

# Run on all interfaces (less secure, useful for remote access)
./server.py --ip 0.0.0.0

# Run on a specific IP and custom port
./server.py --ip 192.168.1.100 --port 8080

# Run with debug mode
./server.py --debug
```

### On your MCP client machine

This can be local (on the same Kali machine) or remote (another Linux machine, Windows or macOS).

If you're running the client and server on the same _Kali_ machine (aka local), run either:

```bash
## OS package
kali-server-mcp --server http://127.0.0.1:5000

# ...OR...

## Bleeding edge
./client.py --server http://127.0.0.1:5000
```

---

If separate machines (aka remote), create an SSH tunnel to your MCP server, then launch the client:

```bash
## Terminal 1 - Replace `LINUX_IP` with Kali's IP
ssh -L 5000:localhost:5000 user@LINUX_IP

## Terminal 2
git clone https://github.com/Wh0am123/MCP-Kali-Server.git
cd MCP-Kali-Server
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
./client.py --server http://127.0.0.1:5000
```

---

If you're openly hosting the MCP Kali server on your network (`server.py --IP...`), you don't need the SSH tunnel (but we do recommend it!)
NOTE: ⚠️(THIS IS STRONGLY DISCOURAGED. WE RECOMMEND SSH)⚠️.

```bash
./client.py --server http://LINUX_IP:5000
```

#### Configuration for Claude Desktop:

Edit:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

[Example MCP-Kali-Server.json](mcp-kali-server.json)

#### Configuration for 5ire Desktop Application:

- Simply add an MCP with the command `python3 /absolute/path/to/client.py --server http://LINUX_IP:5000` and it will automatically generate the needed configuration files.

## 🔮 Other Possibilities

There are more possibilities than described since the AI model can now execute commands on the terminal. Here are some examples:

- Memory forensics using Volatility
  - Automating memory analysis tasks such as process enumeration, DLL injection checks, and registry extraction from memory dumps.

- Disk forensics with SleuthKit
  - Automating analysis from disk images, timeline generation, file carving, and hash comparisons.

## ⚠️ Disclaimer:

This project is intended solely for educational and ethical testing purposes. Any misuse of the information or tools provided — including unauthorized access, exploitation, or malicious activity — is strictly prohibited.

The author assumes no responsibility for misuse.
