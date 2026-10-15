#!/usr/bin/env bash
# =============================================================================
#  internal_discovery.sh — Internal Network Discovery & Recon Pipeline
#
#  Standalone tool. Chains: naabu (live-host + port discovery, no NSE) →
#  nmap -A (targeted deep dive on discovered ports only) → nmap UDP top-100
#  → httpx → gowitness → nuclei (DoS templates excluded).
#
#  For authorized internal security engagements only.
#  Bash 3.2+ compatible (works on default macOS bash) — designed to run on
#  Linux (apt/dnf/yum) engagement boxes, macOS (brew) supported for dev/test.
# =============================================================================

set -euo pipefail

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m';  GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m';  MAGENTA='\033[0;35m'
BOLD='\033[1m';    DIM='\033[2m';      NC='\033[0m'

# ── Spinner PID tracker — updated by run(); read by _cleanup() ────────────────
_SPINNER_PID=""
LOCK_FILE=""

_cleanup() {
  [ -n "$_SPINNER_PID" ] && kill "$_SPINNER_PID" 2>/dev/null || true
  tput cnorm 2>/dev/null || true   # always restore cursor
  printf "\r\033[K"                # clear any partial spinner line
  [ -n "$LOCK_FILE" ] && rm -f "$LOCK_FILE" 2>/dev/null || true
}
trap _cleanup EXIT INT TERM

# ── Logging helpers ───────────────────────────────────────────────────────────
section() {
  echo ""
  echo -e "${BOLD}${MAGENTA}╔══════════════════════════════════════════════╗${NC}"
  printf "${BOLD}${MAGENTA}║  %-44s║${NC}\n" "$1"
  echo -e "${BOLD}${MAGENTA}╚══════════════════════════════════════════════╝${NC}"
}
info()     { echo -e "${BLUE}[*]${NC} $*"; }
ok()       { echo -e "${GREEN}[+]${NC} $*"; }
warn()     { echo -e "${YELLOW}[!]${NC} $*"; }
err()      { echo -e "${RED}[-]${NC} $*"; }
cmd_echo() { echo -e "    ${CYAN}→${NC} $*"; }

has() { command -v "$1" &>/dev/null; }

linecount() { [ -f "$1" ] && wc -l < "$1" | tr -d ' ' || echo "0"; }

# ── Tool resolution ────────────────────────────────────────────────────────
# `go install` always drops binaries in ~/go/bin. We resolve naabu/httpx/
# gowitness/nuclei there explicitly instead of trusting PATH lookup order,
# because PATH collisions are real: e.g. pip's `httpx[cli]` package installs
# its own unrelated `httpx` CLI ("Usage: httpx [OPTIONS] URL", no -l flag) —
# if that shadows ProjectDiscovery's httpx in PATH, `command -v httpx` would
# silently hand us the wrong tool. Override any of these via env var
# (e.g. HTTPX_BIN=/opt/pd/httpx) if your install lives somewhere else.
GO_BIN_DIR="${HOME}/go/bin"
resolve_bin() {
  local name="$1"
  if [ -x "$GO_BIN_DIR/$name" ]; then
    echo "$GO_BIN_DIR/$name"
  else
    command -v "$name" 2>/dev/null || true
  fi
}

# GNU `timeout` isn't on stock macOS (no coreutils by default) — detect a
# working binary once; fall back to running without a cap if neither exists.
TIMEOUT_BIN=""
if has timeout; then TIMEOUT_BIN="timeout"
elif has gtimeout; then TIMEOUT_BIN="gtimeout"
fi

_spinner() {
  local label="$1"
  local frames=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
  local i=0
  tput civis 2>/dev/null || true
  while true; do
    printf "\r  ${CYAN}${frames[$i]}${NC}  %-55s" "$label..."
    i=$(( (i + 1) % ${#frames[@]} ))
    sleep 0.1
  done
}

# Run a labelled command with a live spinner, timeout, and elapsed time; never aborts on non-zero
run() {
  local label="$1"; shift
  cmd_echo "$*"
  echo "[$(date '+%H:%M:%S')] $label: $*" >> "$LOG_FILE"

  _spinner "$label" &
  _SPINNER_PID=$!

  local _start=$SECONDS
  local exit_code=0
  # `|| exit_code=$?` (not a bare statement) so a non-zero tool exit doesn't
  # trip `set -e` and silently kill the whole script — that defeats the
  # entire point of this wrapper, which is to survive individual tool failures.
  if [ -n "$TIMEOUT_BIN" ]; then
    "$TIMEOUT_BIN" "$TOOL_TIMEOUT" "$@" >>"$LOG_FILE" 2>&1 || exit_code=$?
  else
    "$@" >>"$LOG_FILE" 2>&1 || exit_code=$?
  fi
  local _elapsed=$(( SECONDS - _start ))

  kill "$_SPINNER_PID" 2>/dev/null || true
  wait "$_SPINNER_PID" 2>/dev/null || true
  _SPINNER_PID=""
  tput cnorm 2>/dev/null || true
  printf "\r\033[K"

  local _dur
  if [ "$_elapsed" -ge 60 ]; then
    _dur="$(( _elapsed / 60 ))m$(( _elapsed % 60 ))s"
  else
    _dur="${_elapsed}s"
  fi

  if [ "$exit_code" -eq 0 ]; then
    ok "$label ${DIM}(${_dur})${NC}"
  elif [ "$exit_code" -eq 124 ]; then
    warn "$label — timed out after ${TOOL_TIMEOUT}s"
  else
    warn "$label — returned non-zero in ${_dur} (see log)"
  fi
}

# ── OS / package manager detection ────────────────────────────────────────────
PKG_MGR=""

detect_pkg_manager() {
  local os_type; os_type=$(uname -s) || true
  case "$os_type" in
    Darwin)
      if ! has brew; then
        info "Homebrew not found — installing..."
        NONINTERACTIVE=1 /bin/bash -c \
          "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" \
          || { err "Homebrew install failed. Visit https://brew.sh"; return 1; }
        [ -f /opt/homebrew/bin/brew ] && eval "$(/opt/homebrew/bin/brew shellenv)"
        ok "Homebrew installed."
      fi
      PKG_MGR="brew"
      ok "OS: macOS  |  package manager: brew"
      ;;
    Linux)
      if has apt-get; then PKG_MGR="apt"
      elif has dnf; then PKG_MGR="dnf"
      elif has yum; then PKG_MGR="yum"
      else err "No supported package manager found (apt / dnf / yum)."; return 1
      fi
      ok "OS: Linux  |  package manager: $PKG_MGR"
      ;;
    *)
      err "Unsupported OS: $os_type"
      return 1
      ;;
  esac
}

pkg_install() {
  local pkg="$1"
  case "$PKG_MGR" in
    brew) brew install "$pkg" 2>&1 | tail -5 ;;
    apt)  $SUDO apt-get install -y "$pkg" 2>&1 | tail -5 ;;
    dnf)  $SUDO dnf install -y "$pkg" 2>&1 | tail -5 ;;
    yum)  $SUDO yum install -y "$pkg" 2>&1 | tail -5 ;;
  esac
}

# ── Python 3 environment check ────────────────────────────────────────────────
check_python3_env() {
  section "Python 3 Environment"
  [ -z "$PKG_MGR" ] && detect_pkg_manager
  local SUDO=""
  [ "$(id -u)" -ne 0 ] && [ "$PKG_MGR" != "brew" ] && SUDO="sudo"

  if ! has python3; then
    warn "python3 not found — installing..."
    case "$PKG_MGR" in
      brew) brew install python3 ;;
      apt)  $SUDO apt-get install -y python3 python3-pip python3-venv ;;
      dnf)  $SUDO dnf install -y python3 python3-pip ;;
      yum)  $SUDO yum install -y python3 python3-pip ;;
    esac || { err "Failed to install python3."; return 1; }
  fi
  ok "python3 : $(python3 --version 2>&1)"

  if ! has pip3; then
    warn "pip3 not found — bootstrapping via ensurepip..."
    python3 -m ensurepip --upgrade 2>/dev/null || true
    if ! has pip3; then
      case "$PKG_MGR" in
        apt) $SUDO apt-get install -y python3-pip 2>/dev/null || true ;;
        dnf) $SUDO dnf install -y python3-pip 2>/dev/null || true ;;
        yum) $SUDO yum install -y python3-pip 2>/dev/null || true ;;
      esac
    fi
    if ! has pip3; then
      err "pip3 still not available. Install python3-pip manually."
      return 1
    fi
  fi
  ok "pip3    : $(pip3 --version 2>&1)"

  local go_bin="${HOME}/go/bin"
  if [ -d "$go_bin" ] && [[ ":$PATH:" != *":$go_bin:"* ]]; then
    export PATH="$go_bin:$PATH"
    ok "Added Go bin to PATH: $go_bin"
  elif [ -d "$go_bin" ]; then
    ok "Go bin already in PATH: $go_bin"
  else
    warn "~/go/bin does not exist yet — created after first 'go install'"
  fi

  ok "Python 3 environment check complete."
}

# =============================================================================
#  GLOBALS — this script's own state
# =============================================================================
PROJECT_NAME=""
TARGET_INPUT=""
OUTPUT_DIR=""
LOG_FILE=""
VENV_DIR=""
PYBIN=""
EUID_IS_ROOT=0
SCAN_START=0

# — Tunables (override via env, e.g. NAABU_RATE=5000 ./internal_discovery.sh ...) —
# The profile-sensitive ones below are intentionally left unset here (empty)
# rather than defaulted — apply_scan_profile() fills in the right default per
# --internal/--external, but only for whatever the environment didn't already
# set. Non-profile-sensitive tunables keep their normal eager defaults.
SCAN_PROFILE="${SCAN_PROFILE:-internal}"  # internal (default) | external — set via --internal/--external
PORT_SCOPE_EXPLICIT=0                     # 1 once --top-ports/--all-ports is passed — profile must not override it
NAABU_RATE="${NAABU_RATE:-}"              # packets/sec
NAABU_CONC="${NAABU_CONC:-}"              # naabu host concurrency
TCP_TOP_PORTS="${TCP_TOP_PORTS:-}"        # empty = full 1-65535 range; set via --top-ports/--all-ports
SKIP_HOST_DISCOVERY="${SKIP_HOST_DISCOVERY:-0}"  # 1 = --no-ping: skip Phase 1 entirely
NMAP_TIMING="${NMAP_TIMING:-}"
NMAP_MIN_RATE="${NMAP_MIN_RATE:-}"        # Phase 3's -A deep scan floor pps — empty means omit --min-rate entirely
NMAP_HOST_TIMEOUT="${NMAP_HOST_TIMEOUT:-}"       # Phase 3: cap per-host time so one bad host can't stall/kill the whole scan
NMAP_UDP_HOST_TIMEOUT="${NMAP_UDP_HOST_TIMEOUT:-}"
NMAP_TCP_MAX_RETRIES="${NMAP_TCP_MAX_RETRIES:-}"
NMAP_UDP_MAX_RETRIES="${NMAP_UDP_MAX_RETRIES:-}"
UDP_TOP_PORTS="${UDP_TOP_PORTS:-100}"     # fixed scope per requirement
THREADS="${THREADS:-50}"                  # httpx/nuclei/gowitness concurrency
NUCLEI_RATE="${NUCLEI_RATE:-150}"         # requests/sec for nuclei
TOOL_TIMEOUT="${TOOL_TIMEOUT:-1800}"      # seconds per phase before it's killed
GOWITNESS_DRIVER="${GOWITNESS_DRIVER:-gorod}"  # gorod auto-downloads Chromium if none found; chromedp needs system Chrome

# naabu host-discovery probe flags and extra nmap flags — filled per-profile
# by apply_scan_profile() (arrays, so they can't use the "${VAR:-}" idiom).
NAABU_DISCOVERY_FLAGS=()
NMAP_EXTRA_FLAGS=()

# Fill in whatever the profile/environment didn't already set. Call once,
# after CLI parsing, before any phase runs.
apply_scan_profile() {
  # Ports for TCP SYN/ACK host-discovery probes — naabu's own embedded
  # "NmapTop100" list (pkg/runner/ports.go), the same 100 ports nmap's
  # --top-ports 100 draws from. A hand-picked handful of ports (80/443/etc)
  # misses anything listening on, say, 8081 or 5900 — a host that drops
  # ICMP outright (very common at internet edges, and on Windows boxes
  # internally, which block ping by default via Windows Firewall) would
  # then look "down" even though it's reachable on a port just outside
  # whatever short list was guessed. Top-100 gives discovery the same
  # port coverage a standard nmap sweep would use.
  local disc_ports="7,9,13,21-23,25-26,37,53,79-81,88,106,110-111,113,119,135,139,143-144,179,199,389,427,443-445,465,513-515,543-544,548,554,587,631,646,873,990,993,995,1025-1029,1110,1433,1720,1723,1755,1900,2000-2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000-6001,6646,7070,8000,8008-8009,8080-8081,8443,8888,9100,9999-10000,32768,49152-49157"

  case "$SCAN_PROFILE" in
    internal)
      : "${NAABU_RATE:=2000}"           # LAN bandwidth is cheap, push hard
      : "${NAABU_CONC:=25}"
      : "${NMAP_TIMING:=-T4}"           # low latency, safe to push
      : "${NMAP_MIN_RATE:=1000}"
      : "${NMAP_HOST_TIMEOUT:=5m}"
      : "${NMAP_UDP_HOST_TIMEOUT:=3m}"
      : "${NMAP_TCP_MAX_RETRIES:=2}"
      : "${NMAP_UDP_MAX_RETRIES:=1}"
      # ARP is the reliable signal here (works even when ICMP is
      # firewalled locally) — ICMP and TCP SYN are extra confirmation.
      NAABU_DISCOVERY_FLAGS=(-ping -arp-ping -probe-tcp-syn "$disc_ports")
      NMAP_EXTRA_FLAGS=()
      ;;
    external)
      : "${NAABU_RATE:=150}"            # conservative — avoid tripping WAF/IDS, respect ROE
      : "${NAABU_CONC:=15}"
      : "${NMAP_TIMING:=-T3}"           # internet RTT is variable; -T4 misreads latency as loss
      # NMAP_MIN_RATE left empty on purpose — let nmap's own congestion
      # control pace the scan instead of forcing a floor over an unknown path.
      : "${NMAP_HOST_TIMEOUT:=15m}"
      : "${NMAP_UDP_HOST_TIMEOUT:=10m}"
      : "${NMAP_TCP_MAX_RETRIES:=4}"    # real loss/congestion on the internet — compensate
      : "${NMAP_UDP_MAX_RETRIES:=2}"
      # No -arp-ping (doesn't route off-segment). TCP SYN/ACK to the
      # top-100 ports is the primary signal here, not ICMP — most internet
      # edges drop ping but still forward traffic to whatever's listening.
      NAABU_DISCOVERY_FLAGS=(-ping -probe-tcp-syn "$disc_ports" -probe-tcp-ack "$disc_ports")
      NMAP_EXTRA_FLAGS=(--defeat-rst-ratelimit)  # cloud LBs/SYN-cookie DDoS protection rate-limit RSTs
      if [ "$PORT_SCOPE_EXPLICIT" -eq 0 ] && [ -z "$TCP_TOP_PORTS" ]; then
        TCP_TOP_PORTS=1000               # full 65535 externally is slow and noisy by default
      fi
      ;;
    *)
      err "Unknown scan profile: $SCAN_PROFILE (expected internal or external)"
      exit 1
      ;;
  esac
  ok "Scan profile: ${BOLD}$SCAN_PROFILE${NC}"
}

# Resolved tool paths — see resolve_bin() above for why these aren't just
# bare command names. Override any of them via env var if needed.
NMAP_BIN="${NMAP_BIN:-$(resolve_bin nmap)}"
NAABU_BIN="${NAABU_BIN:-$(resolve_bin naabu)}"
HTTPX_BIN="${HTTPX_BIN:-$(resolve_bin httpx)}"
GOWITNESS_BIN="${GOWITNESS_BIN:-$(resolve_bin gowitness)}"
NUCLEI_BIN="${NUCLEI_BIN:-$(resolve_bin nuclei)}"

# Tools this workflow needs.
DEPS_LOCAL=(
  "nmap:system:nmap"
  "naabu:go:github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
  "httpx:go:github.com/projectdiscovery/httpx/cmd/httpx@latest"
  "gowitness:go:github.com/sensepost/gowitness@latest"
  "nuclei:go:github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
)

# =============================================================================
#  PRE-FLIGHT
# =============================================================================

preflight_check() {
  section "PRE-FLIGHT CHECK"

  [ "$(id -u)" -eq 0 ] && EUID_IS_ROOT=1 || EUID_IS_ROOT=0

  detect_pkg_manager || true
  check_python3_env || true   # also exports ~/go/bin into PATH if present

  local missing=()

  for dep in "${DEPS_LOCAL[@]}"; do
    local tool="${dep%%:*}"
    local bin_var; bin_var="$(echo "$tool" | tr '[:lower:]' '[:upper:]')_BIN"
    local bin_path="${!bin_var}"
    if [ -n "$bin_path" ] && [ -x "$bin_path" ]; then
      ok "$(printf '%-10s' "$tool") $bin_path"
      if [ "$tool" = "httpx" ] && ! [[ "$bin_path" == "$GO_BIN_DIR"/* ]]; then
        warn "  ^ resolved via PATH, not ~/go/bin — double-check this is ProjectDiscovery's httpx."
      fi
    else
      err "$(printf '%-10s' "$tool") not found"
      missing+=("$tool")
    fi
  done

  # Signature check — the confirmed real-world collision: pip's httpx[cli]
  # package installs a `httpx` binary too, with completely different flags
  # ("Usage: httpx [OPTIONS] URL", no -l). If PATH resolved that one instead
  # of ~/go/bin/httpx, catch it here rather than mid-scan.
  if [ -n "$HTTPX_BIN" ]; then
    local sig; sig=$("$HTTPX_BIN" -version 2>&1 || true)
    if echo "$sig" | grep -qiE "no such option|Usage: httpx \[OPTIONS\] URL"; then
      err "httpx at $HTTPX_BIN is NOT ProjectDiscovery's httpx (looks like Python's httpx[cli] package)."
      err "Fix: run this script's -e installer (installs the real one to ~/go/bin), or set HTTPX_BIN=/path/to/projectdiscovery/httpx"
      missing+=("httpx")
    fi
  fi

  # go itself (needed to install the go: tools above)
  if ! has go && [ "${#missing[@]}" -gt 0 ]; then
    err "$(printf '%-10s' "go")   not found — required to install: ${missing[*]}"
  fi

  if [ -z "$TIMEOUT_BIN" ]; then
    warn "No 'timeout' or 'gtimeout' binary found — phases will run with NO time cap."
    warn "  macOS: brew install coreutils   (provides gtimeout)"
    warn "  A hung tool will block the pipeline until you Ctrl-C it."
  else
    ok "Timeout wrapper: $TIMEOUT_BIN (cap: ${TOOL_TIMEOUT}s/phase)"
  fi

  # libpcap — naabu's raw-packet router needs it on Linux for ARP/ICMP/TCP
  # discovery probes. Without it, naabu can't tell it's discovery-capable
  # even with -host-discovery set, and will hard-fail with "discovery
  # probes were provided but host discovery is disabled" the moment Phase 1
  # runs — not a targeting problem, this dependency specifically.
  if [ "$(uname -s)" = "Linux" ] && [ -n "$NAABU_BIN" ]; then
    if ! ldconfig -p 2>/dev/null | grep -q libpcap; then
      warn "libpcap not detected — Phase 1 host discovery will hard-fail, not just degrade."
      warn "Install with: sudo apt install -y libpcap-dev  (or dnf/yum equivalent)"
    fi
  fi

  # root / raw-socket capability
  if [ "$EUID_IS_ROOT" -eq 0 ]; then
    warn "Not running as root."
    warn "  naabu will fall back to CONNECT scans (-s c) instead of SYN."
    warn "  nmap -A will skip OS detection (-O) and run a TCP connect scan."
    warn "  nmap UDP scanning (-sU) requires root and will be SKIPPED entirely."
    warn "Re-run with sudo for full-fidelity results."
  else
    ok "Running as root — SYN scan, OS detection, and UDP scan all available."
  fi

  if [ "${#missing[@]}" -gt 0 ]; then
    echo ""
    err "Missing required tools: ${missing[*]}"
    err "Run: $0 -e   to install them."
    return 1
  fi

  ok "All required tools present."
  return 0
}

install_deps_local() {
  section "INSTALLING DEPENDENCIES"

  detect_pkg_manager || return 1

  local SUDO=""
  [ "$(id -u)" -ne 0 ] && [ "$PKG_MGR" != "brew" ] && SUDO="sudo"

  # ── Go itself ────────────────────────────────────────────────────────────
  if ! has go; then
    info "Go not found — installing..."
    case "$PKG_MGR" in
      brew) brew install go ;;
      apt)  $SUDO apt install -y golang ;;
      dnf)  $SUDO dnf install -y golang ;;
      yum)  $SUDO yum install -y golang ;;
    esac || { err "Failed to install Go."; return 1; }
    ok "Go installed: $(go version 2>/dev/null)"
  else
    ok "Go: $(go version 2>/dev/null)"
  fi

  # ── libpcap-dev (Linux only — naabu host-discovery / ARP-ICMP probes) ─────
  if [ "$PKG_MGR" = "apt" ]; then
    info "Updating apt index..."
    $SUDO apt update -qq 2>/dev/null || true
    info "Installing libpcap-dev (required by naabu)..."
    $SUDO apt install -y libpcap-dev 2>&1 | tail -3 || warn "libpcap-dev install failed — naabu ARP/ICMP probes may not work."
  elif [ "$PKG_MGR" = "dnf" ] || [ "$PKG_MGR" = "yum" ]; then
    $SUDO "$PKG_MGR" install -y libpcap-devel 2>&1 | tail -3 || true
  fi

  # ── Chromium (best-effort — gowitness) ────────────────────────────────────
  # Not required: gowitness defaults to --driver gorod, which auto-downloads
  # a matching Chromium if it can't find one. Installing it here just saves
  # that download and gives gowitness something to use if egress is
  # restricted. Failure here is non-fatal either way.
  if ! has chromium && ! has chromium-browser && ! has google-chrome; then
    case "$PKG_MGR" in
      apt)  info "Installing chromium (optional — speeds up gowitness)..."
            $SUDO apt install -y chromium 2>&1 | tail -3 \
              || $SUDO apt install -y chromium-browser 2>&1 | tail -3 \
              || warn "chromium install failed — gowitness will auto-download its own Chromium instead." ;;
      dnf)  $SUDO dnf install -y chromium 2>&1 | tail -3 || true ;;
      yum)  $SUDO yum install -y chromium 2>&1 | tail -3 || true ;;
      brew) brew install --cask chromium 2>&1 | tail -3 || true ;;
    esac
  else
    ok "Browser for gowitness already present."
  fi

  # ── python3 / pip3 ───────────────────────────────────────────────────────
  check_python3_env

  # ── Ensure go bin on PATH before installing go-based tools ────────────────
  local go_bin="${HOME}/go/bin"
  [ -d "$go_bin" ] && [[ ":$PATH:" != *":$go_bin:"* ]] && export PATH="$go_bin:$PATH"

  # ── nmap (system package) ──────────────────────────────────────────────────
  if ! has nmap; then
    info "Installing nmap..."
    pkg_install nmap || warn "nmap install failed — install manually."
  else
    ok "nmap: $(nmap --version 2>/dev/null | head -1)"
  fi

  # ── Go-installed tools — exact commands as specified for this workflow ────
  # Checked by ~/go/bin presence, not bare `has`/PATH: a same-named tool
  # from another ecosystem earlier in PATH (e.g. pip's httpx[cli] CLI) would
  # otherwise make `has httpx` report "already installed" and skip the real
  # ProjectDiscovery install entirely.
  if [ ! -x "$go_bin/naabu" ]; then
    info "Installing naabu..."
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest || warn "naabu install failed."
  fi
  if [ ! -x "$go_bin/httpx" ]; then
    info "Installing httpx..."
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest || warn "httpx install failed."
  fi
  if [ ! -x "$go_bin/gowitness" ]; then
    info "Installing gowitness..."
    go install github.com/sensepost/gowitness@latest || warn "gowitness install failed."
  fi
  if [ ! -x "$go_bin/nuclei" ]; then
    info "Installing nuclei..."
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest || warn "nuclei install failed."
  fi

  [ -d "$go_bin" ] && [[ ":$PATH:" != *":$go_bin:"* ]] && export PATH="$go_bin:$PATH"

  # Recompute resolved bins for this process — GO_BIN_DIR is the same path
  # so newly-installed binaries are picked up automatically, but this makes
  # it explicit for anything that ran preflight_check earlier in this process.
  NAABU_BIN="$(resolve_bin naabu)"
  HTTPX_BIN="$(resolve_bin httpx)"
  GOWITNESS_BIN="$(resolve_bin gowitness)"
  NUCLEI_BIN="$(resolve_bin nuclei)"
  NMAP_BIN="$(resolve_bin nmap)"

  echo ""
  ok "Dependency install pass complete."
  local shell_rc
  case "${SHELL:-}" in
    */zsh)  shell_rc="~/.zshrc" ;;
    */bash) shell_rc="~/.bashrc" ;;
    *)      shell_rc="~/.profile" ;;
  esac
  info "Persist Go's bin dir across sessions — add to $shell_rc:"
  echo "    export PATH=\"\$HOME/go/bin:\$PATH\""
  echo ""
  info "Re-run: $0 -n <project> -i <targets>   to verify with a pre-flight check."
}

# =============================================================================
#  PYTHON VENV — any python dependencies for this tool live here, never in
#  the system/global interpreter.
# =============================================================================

# Add packages here if a future report step needs them (e.g. "jinja2").
# Empty today — the summary report below uses stdlib only.
PY_REQUIREMENTS=()

setup_python_env() {
  VENV_DIR="$OUTPUT_DIR/.venv"
  info "Creating Python venv → $VENV_DIR"
  python3 -m venv "$VENV_DIR" 2>>"$LOG_FILE" || { err "Failed to create venv."; return 1; }
  PYBIN="$VENV_DIR/bin/python3"
  "$PYBIN" -m pip install --upgrade pip -q 2>>"$LOG_FILE" || true

  if [ "${#PY_REQUIREMENTS[@]}" -gt 0 ]; then
    info "Installing python deps into venv: ${PY_REQUIREMENTS[*]}"
    "$PYBIN" -m pip install -q "${PY_REQUIREMENTS[@]}" 2>>"$LOG_FILE" || warn "venv pip install failed."
  fi
  ok "Python venv ready: $PYBIN"
}

# =============================================================================
#  PROJECT SETUP
# =============================================================================

setup_project() {
  local _safe_name; _safe_name=$(printf '%s' "$PROJECT_NAME" | tr -dc 'a-zA-Z0-9.-' | tr '.' '_')
  LOCK_FILE="/tmp/internal_discovery_${_safe_name}.lock"
  if [ -f "$LOCK_FILE" ]; then
    local _old_pid; _old_pid=$(cat "$LOCK_FILE" 2>/dev/null)
    if kill -0 "$_old_pid" 2>/dev/null; then
      err "internal_discovery.sh is already running for '$PROJECT_NAME' (PID $_old_pid)"
      err "Kill that process or delete $LOCK_FILE to force a new run."
      exit 1
    else
      warn "Stale lock file found — removing (PID $_old_pid no longer running)"
      rm -f "$LOCK_FILE"
    fi
  fi
  echo $$ > "$LOCK_FILE"

  local _min_mb=500
  local _avail_kb _avail_mb
  _avail_kb=$(df -k . 2>/dev/null | awk 'NR==2 {print $4}') || _avail_kb=0
  _avail_mb=$(( _avail_kb / 1024 ))
  if [ "$_avail_mb" -lt "$_min_mb" ]; then
    err "Insufficient disk space: ${_avail_mb}MB available, ${_min_mb}MB required"
    exit 1
  fi

  OUTPUT_DIR="${PROJECT_NAME}_intdisco_$(date '+%Y%m%d_%H%M%S')"
  mkdir -p "$OUTPUT_DIR"/{hosts,ports,nmap,udp,web,screenshots,vulns}
  LOG_FILE="$OUTPUT_DIR/recon.log"
  touch "$LOG_FILE"
  SCAN_START=$SECONDS
  ok "Project     : ${BOLD}$PROJECT_NAME${NC}"
  ok "Output      : ${BOLD}$OUTPUT_DIR${NC}"

  setup_python_env
}

# Accepts a file path, or a single IP/CIDR/hostname — normalises to a file.
resolve_targets() {
  local raw="$1"
  if [ -f "$raw" ]; then
    TARGET_INPUT="$raw"
    return 0
  fi
  if [[ "$raw" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?$ ]] || [[ "$raw" =~ ^[a-zA-Z0-9.-]+$ ]]; then
    TARGET_INPUT="$OUTPUT_DIR/hosts/targets_input.txt"
    mkdir -p "$OUTPUT_DIR/hosts"
    echo "$raw" > "$TARGET_INPUT"
    return 0
  fi
  err "Target '$raw' is not an existing file and doesn't look like an IP/CIDR/hostname."
  return 1
}

# =============================================================================
#  PHASE 1 — LIVE HOST DISCOVERY (naabu)
# =============================================================================

phase1_host_discovery() {
  local out="$OUTPUT_DIR/hosts"
  section "PHASE 1 — Live Host Discovery (naabu)"

  local total; total=$(grep -c '[^[:space:]]' "$TARGET_INPUT" 2>/dev/null || echo 0)
  ok "Input targets: $total"

  if [ "$SKIP_HOST_DISCOVERY" -eq 1 ]; then
    warn "--no-ping — skipping host discovery entirely, treating all $total input targets as candidates."
    cp "$TARGET_INPUT" "$out/naabu_live_hosts.txt"
    ok "Candidate hosts going into port scan: $(linecount "$out/naabu_live_hosts.txt")"
    return
  fi

  if [ "$EUID_IS_ROOT" -eq 1 ]; then
    # -host-discovery (-sn, "discovery only, skip the scan") is the less
    # exercised naabu code path and has had real regressions there (e.g.
    # projectdiscovery/naabu#1307). -with-host-discovery (-wn, "discovery as
    # a pre-filter for a scan") is the primary, better-tested path — give it
    # a cheap top-100 scope here since we only want liveness out of this
    # step; Phase 2 does the real, full port enumeration separately.
    # naabu tracks discovered-alive hosts independently of port results and
    # writes them as bare IPs (no ":port") when nothing in range is open, so
    # a live host with nothing in the top 100 still shows up here — this
    # cut -d: -f1 below already handles both "ip" and "ip:port" lines.
    run "naabu — host discovery ($SCAN_PROFILE profile)" \
      "$NAABU_BIN" -list "$TARGET_INPUT" -with-host-discovery "${NAABU_DISCOVERY_FLAGS[@]}" \
        -top-ports 100 -silent \
        -o "$out/naabu_discovery_raw.txt"

    # Even on -wn, naabu still needs its raw-packet router to actually run
    # the probes; missing libpcap or a container without NET_RAW/NET_ADMIN
    # leaves it nil, which naabu reports as "discovery probes were provided
    # but host discovery is disabled". Surface *why*, not just the raw fatal
    # line — the fallback below still keeps the pipeline moving either way.
    if grep -qi "discovery probes were provided but host discovery is disabled" "$LOG_FILE" 2>/dev/null; then
      warn "naabu couldn't initialize raw-packet discovery despite running as root."
      warn "  Most likely cause: libpcap runtime library missing. Check: ldconfig -p | grep libpcap"
      warn "  Install: sudo apt install -y libpcap0.8   (Debian/Ubuntu runtime package)"
      warn "  If this is a container: it needs --cap-add=NET_RAW --cap-add=NET_ADMIN (or --privileged)."
    fi

    if [ -s "$out/naabu_discovery_raw.txt" ]; then
      cut -d: -f1 "$out/naabu_discovery_raw.txt" | sort -u > "$out/naabu_live_hosts.txt"
    else
      : > "$out/naabu_live_hosts.txt"
    fi
  else
    warn "Non-root — skipping dedicated ICMP/ARP discovery (needs raw sockets)."
    warn "Host liveness will be inferred from Phase 2's port-scan results instead."
    cp "$TARGET_INPUT" "$out/naabu_live_hosts.txt"
  fi

  local live; live=$(linecount "$out/naabu_live_hosts.txt")
  if [ "$live" -eq 0 ]; then
    warn "No hosts confirmed via discovery probes — falling back to full input list."
    warn "This means Phase 2 will port-scan every input address, not just confirmed-live ones."
    cp "$TARGET_INPUT" "$out/naabu_live_hosts.txt"
  fi
  ok "Candidate hosts going into port scan: $(linecount "$out/naabu_live_hosts.txt")"
}

# =============================================================================
#  PHASE 2 — FAST PORT SCAN, NO NSE SCRIPTS (naabu)
# =============================================================================

phase2_port_scan() {
  local out="$OUTPUT_DIR/ports"
  section "PHASE 2 — Port Scan (naabu, no NSE scripts)"

  local scan_type="s"; [ "$EUID_IS_ROOT" -eq 0 ] && scan_type="c"
  local port_flag=(-p -)
  local port_label="full 1-65535"
  if [ -n "$TCP_TOP_PORTS" ]; then
    port_flag=(-top-ports "$TCP_TOP_PORTS")
    port_label="top $TCP_TOP_PORTS"
  fi

  info "Scan type: $([ "$scan_type" = "s" ] && echo SYN || echo CONNECT)  |  Ports: $port_label  |  Rate: $NAABU_RATE pps"
  cmd_echo "naabu -list live_hosts.txt -s $scan_type ${port_flag[*]} -rate $NAABU_RATE -c $NAABU_CONC -silent -o naabu_open.txt"

  run "naabu — TCP port scan" \
    "$NAABU_BIN" -list "$OUTPUT_DIR/hosts/naabu_live_hosts.txt" \
      -s "$scan_type" "${port_flag[@]}" \
      -rate "$NAABU_RATE" -c "$NAABU_CONC" \
      -silent -o "$out/naabu_open.txt"

  if [ ! -s "$out/naabu_open.txt" ]; then
    warn "naabu found no open TCP ports — later phases will have nothing to work with."
    touch "$out/open_ports_union.txt" "$OUTPUT_DIR/hosts/live_hosts.txt"
    return
  fi

  # naabu's default -o format is "ip:port" per line — derive everything from it.
  cut -d: -f1 "$out/naabu_open.txt" | sort -u > "$OUTPUT_DIR/hosts/live_hosts.txt"
  awk -F: '{print $NF}' "$out/naabu_open.txt" | sort -un | paste -sd, - > "$out/open_ports_union.txt"

  local live_count port_count
  live_count=$(linecount "$OUTPUT_DIR/hosts/live_hosts.txt")
  port_count=$(awk -F: '{print $NF}' "$out/naabu_open.txt" | sort -un | wc -l | tr -d ' ')
  ok "Hosts with open ports : $live_count"
  ok "Unique open ports     : $port_count"
  ok "Ports                 : $(cat "$out/open_ports_union.txt")"
}

# =============================================================================
#  PHASE 3 — TARGETED DEEP SCAN (nmap -A on discovered ports only)
# =============================================================================

phase3_nmap_deep() {
  local out="$OUTPUT_DIR/nmap"
  local ports; ports=$(cat "$OUTPUT_DIR/ports/open_ports_union.txt" 2>/dev/null)
  section "PHASE 3 — nmap -A Deep Scan (TCP, discovered ports only)"

  if [ -z "$ports" ]; then
    warn "No open ports from Phase 2 — skipping nmap -A."
    return
  fi

  local pn_flag="-Pn"   # hosts already confirmed live — skip nmap's own ping

  # Build the arg list into one array instead of expanding rate_flag/
  # NMAP_EXTRA_FLAGS as standalone "${arr[@]}" pieces: under set -u, bash 3.2
  # (stock macOS) throws "unbound variable" on an EMPTY array's [@]/[*]
  # expansion. nmap_args itself is never empty (always has -A etc), so
  # expanding it directly is safe; the possibly-empty pieces are only ever
  # appended into it (length-checked first for NMAP_EXTRA_FLAGS).
  local nmap_args=(-A $NMAP_TIMING $pn_flag -n)
  [ -n "$NMAP_MIN_RATE" ] && nmap_args+=(--min-rate "$NMAP_MIN_RATE")
  nmap_args+=(--max-retries "$NMAP_TCP_MAX_RETRIES" --version-intensity 5 --script-timeout 30s --host-timeout "$NMAP_HOST_TIMEOUT")
  [ "${#NMAP_EXTRA_FLAGS[@]}" -gt 0 ] && nmap_args+=("${NMAP_EXTRA_FLAGS[@]}")
  nmap_args+=(--open --reason -p "$ports" -iL "$OUTPUT_DIR/hosts/live_hosts.txt" -oA "$out/deep_tcp")

  cmd_echo "nmap ${nmap_args[*]}"
  run "nmap -A — targeted deep scan ($SCAN_PROFILE profile)" "$NMAP_BIN" "${nmap_args[@]}"

  ok "Deep scan complete → $out/deep_tcp.{nmap,gnmap,xml}"
}

# =============================================================================
#  PHASE 4 — UDP SCAN (fixed --top-ports 100)
# =============================================================================

phase4_udp_scan() {
  local out="$OUTPUT_DIR/udp"
  section "PHASE 4 — UDP Scan (--top-ports $UDP_TOP_PORTS)"

  if [ "$EUID_IS_ROOT" -eq 0 ]; then
    warn "UDP scanning requires root — skipping Phase 4 entirely."
    return
  fi

  cmd_echo "nmap -sU --top-ports $UDP_TOP_PORTS $NMAP_TIMING -Pn -n --min-rate 300 --max-retries $NMAP_UDP_MAX_RETRIES --host-timeout $NMAP_UDP_HOST_TIMEOUT --open -iL live_hosts.txt"

  run "nmap -sU — UDP top $UDP_TOP_PORTS ($SCAN_PROFILE profile)" \
    "$NMAP_BIN" -sU --top-ports "$UDP_TOP_PORTS" $NMAP_TIMING -Pn -n \
      --min-rate 300 --max-retries "$NMAP_UDP_MAX_RETRIES" \
      --host-timeout "$NMAP_UDP_HOST_TIMEOUT" \
      --open --reason \
      -iL "$OUTPUT_DIR/hosts/live_hosts.txt" \
      -oA "$out/udp_top${UDP_TOP_PORTS}"

  ok "UDP scan complete → $out/udp_top${UDP_TOP_PORTS}.{nmap,gnmap,xml}"
}

# =============================================================================
#  PHASE 5 — WEB ENUMERATION (httpx)
# =============================================================================

phase5_httpx() {
  local out="$OUTPUT_DIR/web"
  local seed="$OUTPUT_DIR/ports/naabu_open.txt"
  section "PHASE 5 — Web Enumeration (httpx)"

  if [ ! -s "$seed" ]; then
    warn "No open ports to probe — skipping httpx."
    return
  fi

  run "httpx — clean URL list" \
    "$HTTPX_BIN" -l "$seed" -silent -threads "$THREADS" -o "$out/httpx_urls.txt"

  run "httpx — enriched recon (title/status/tech)" \
    "$HTTPX_BIN" -l "$seed" -silent -status-code -title -tech-detect -follow-redirects \
      -threads "$THREADS" -o "$out/httpx_results.txt"

  local web_count; web_count=$(linecount "$out/httpx_urls.txt")
  ok "Live web endpoints: $web_count"
}

# =============================================================================
#  PHASE 6 — SCREENSHOTS (gowitness)
# =============================================================================

phase6_gowitness() {
  local out="$OUTPUT_DIR/screenshots"
  local urls="$OUTPUT_DIR/web/httpx_urls.txt"
  section "PHASE 6 — Screenshots (gowitness)"

  if [ ! -s "$urls" ]; then
    warn "No web endpoints — skipping gowitness."
    return
  fi

  # gowitness v3 (sensepost) subcommand syntax — check `gowitness scan file --help`
  # if you've pinned an older v2 binary, which used `gowitness file -f ...`.
  #
  # --driver gorod (not the chromedp default): chromedp requires a
  # pre-installed "google-chrome" on PATH and fails outright without one
  # ("exec: google-chrome: executable file not found in $PATH") — common on
  # minimal engagement boxes. go-rod auto-downloads a matching Chromium
  # build when no browser is found, so it works without a system install.
  # Force chromedp back with GOWITNESS_DRIVER=chromedp if you've already
  # got Chrome installed and prefer it.
  run "gowitness — screenshot web targets" \
    "$GOWITNESS_BIN" scan file -f "$urls" \
      --driver "$GOWITNESS_DRIVER" \
      --screenshot-path "$out" \
      --write-db --write-db-uri "sqlite://$out/gowitness.sqlite3" \
      --threads "$THREADS"

  ok "Screenshots → $out/"
}

# =============================================================================
#  PHASE 7 — VULNERABILITY SCAN (nuclei, DoS templates excluded)
# =============================================================================

phase7_nuclei() {
  local out="$OUTPUT_DIR/vulns"
  local urls="$OUTPUT_DIR/web/httpx_urls.txt"
  section "PHASE 7 — Vulnerability Scan (nuclei, -etags dos)"

  if [ ! -s "$urls" ]; then
    warn "No web endpoints — skipping nuclei."
    return
  fi

  run "nuclei — vuln scan (DoS excluded)" \
    "$NUCLEI_BIN" -l "$urls" \
      -etags dos \
      -rate-limit "$NUCLEI_RATE" -c "$THREADS" \
      -o "$out/nuclei_results.txt" -stats

  local finding_count; finding_count=$(linecount "$out/nuclei_results.txt")
  ok "Findings: $finding_count  → $out/nuclei_results.txt"
}

# =============================================================================
#  SUMMARY
# =============================================================================

generate_summary() {
  section "SUMMARY"
  local summary="$OUTPUT_DIR/00_summary.txt"
  local elapsed=$(( SECONDS - SCAN_START ))
  local dur; if [ "$elapsed" -ge 60 ]; then dur="$(( elapsed / 60 ))m$(( elapsed % 60 ))s"; else dur="${elapsed}s"; fi

  {
    printf '=%.0s' {1..60}; echo
    printf "  INTERNAL DISCOVERY SUMMARY\n"
    printf "  Project    : %s\n" "$PROJECT_NAME"
    printf "  Targets    : %s\n" "$TARGET_INPUT"
    printf "  Completed  : %s (%s elapsed)\n" "$(date)" "$dur"
    printf '=%.0s' {1..60}; echo
    echo ""
    printf "  %-28s %s\n" "Live hosts:"        "$(linecount "$OUTPUT_DIR/hosts/live_hosts.txt")"
    printf "  %-28s %s\n" "Open TCP ports:"    "$(cat "$OUTPUT_DIR/ports/open_ports_union.txt" 2>/dev/null)"
    printf "  %-28s %s\n" "Web endpoints:"     "$(linecount "$OUTPUT_DIR/web/httpx_urls.txt")"
    printf "  %-28s %s\n" "Nuclei findings:"   "$(linecount "$OUTPUT_DIR/vulns/nuclei_results.txt")"
    echo ""
    echo "  Output tree:"
    printf "    %s\n" "$OUTPUT_DIR/hosts/  ports/  nmap/  udp/  web/  screenshots/  vulns/"
    printf "    %s\n" "$OUTPUT_DIR/recon.log  (every command run, timestamped)"
    printf '=%.0s' {1..60}; echo
  } | tee "$summary"

  ok "Summary → $summary"
}

# =============================================================================
#  CLI
# =============================================================================

usage() {
  echo ""
  echo -e "${BOLD}Usage:${NC}"
  echo "  ./internal_discovery.sh -n <project-name> -i <targets> [options]"
  echo ""
  echo -e "${BOLD}Required:${NC}"
  echo "  -n, --name <name>     Project name — used for the output directory and lock file"
  echo "  -i, --targets <t>     Targets file (IP/CIDR/hostname per line), or a single IP/CIDR"
  echo ""
  echo -e "${BOLD}Options:${NC}"
  echo "  -e, --install         Install/verify required tools (nmap, naabu, httpx, gowitness, nuclei) then exit"
  echo "      --internal        Tune every phase for a LAN target (default) — aggressive timing/rate,"
  echo "                        ARP+ICMP host discovery, full port range"
  echo "      --external        Tune every phase for an internet-facing target — conservative timing/rate,"
  echo "                        no ARP probing, higher retries, top-1000 ports by default, wider host timeouts"
  echo "      --all-ports       Scan all 65535 TCP ports (overrides the profile's port-scope default)"
  echo "      --top-ports <N>   Scan only naabu's top N TCP ports (e.g. --top-ports 1000) — faster, less thorough"
  echo "      --no-ping         Skip Phase 1 host discovery entirely — treat every input target as a"
  echo "                        candidate and go straight to the port scan (also useful when ICMP/ARP"
  echo "                        probes are undesirable, e.g. stealth or IDS-sensitive segments)"
  echo "  -h, --help            Show this help"
  echo ""
  echo -e "${BOLD}Pipeline:${NC}"
  echo "  1. naabu    — live host discovery (skipped with --no-ping; TCP-SYN-based on --external)"
  echo "  2. naabu    — port scan, no NSE scripts"
  echo "  3. nmap -A  — deep scan, scoped to discovered ports only"
  echo "  4. nmap -sU — UDP scan, --top-ports $UDP_TOP_PORTS (root only)"
  echo "  5. httpx    — web enumeration"
  echo "  6. gowitness— screenshots"
  echo "  7. nuclei   — vulnerability scan (-etags dos)"
  echo ""
  echo -e "${BOLD}--internal vs --external, what actually changes:${NC}"
  echo "  Setting              internal (default)    external"
  echo "  naabu rate/conc      2000 pps / 25          150 pps / 15"
  echo "  nmap timing          -T4                    -T3"
  echo "  nmap --min-rate      1000                   (omitted — let nmap pace itself)"
  echo "  nmap TCP retries     2                       4"
  echo "  nmap UDP retries     1                       2"
  echo "  nmap host-timeout    5m TCP / 3m UDP          15m TCP / 10m UDP"
  echo "  default port scope   full 65535               top 1000"
  echo "  naabu host discovery ARP+ICMP+TCP-SYN            ICMP+TCP-SYN/ACK (no ARP off-segment)"
  echo "  extra nmap flags     —                        --defeat-rst-ratelimit"
  echo ""
  echo -e "${BOLD}Examples:${NC}"
  echo "  sudo ./internal_discovery.sh -n acme-internal -i targets.txt"
  echo "  sudo ./internal_discovery.sh -n acme-internal -i 10.10.20.0/24"
  echo "  sudo ./internal_discovery.sh -n acme-external -i external_ips.txt --external"
  echo "  sudo ./internal_discovery.sh -n acme-internal -i targets.txt --top-ports 1000"
  echo "  sudo ./internal_discovery.sh -n acme-internal -i targets.txt --no-ping"
  echo "  ./internal_discovery.sh -e                         # install/verify tools"
  echo ""
  echo -e "${BOLD}Environment overrides:${NC}"
  echo "  (all of these are set per-profile by --internal/--external — an explicit env value always wins)"
  echo "  SCAN_PROFILE=external same as --external"
  echo "  NAABU_RATE=5000       naabu packets/sec"
  echo "  NAABU_CONC=50         naabu host concurrency"
  echo "  TCP_TOP_PORTS=1000    same as --top-ports (empty = --all-ports)"
  echo "  SKIP_HOST_DISCOVERY=1 same as --no-ping"
  echo "  NMAP_TIMING=-T3       nmap timing template"
  echo "  NMAP_MIN_RATE=2000    Phase 3 (-A) minimum packets/sec floor (empty = omit the flag)"
  echo "  NMAP_TCP_MAX_RETRIES=3  Phase 3 retry count"
  echo "  NMAP_UDP_MAX_RETRIES=2  Phase 4 retry count"
  echo "  NMAP_HOST_TIMEOUT=10m     Phase 3 per-host cap — a stuck host gets skipped, not the whole scan"
  echo "  NMAP_UDP_HOST_TIMEOUT=5m  Phase 4 per-host cap"
  echo "  NUCLEI_RATE=300       nuclei requests/sec (default 150, not profile-tuned)"
  echo "  THREADS=100           httpx/gowitness/nuclei concurrency (default 50, not profile-tuned)"
  echo "  TOOL_TIMEOUT=3600     seconds per phase before it's killed (default 1800)"
  echo "  GOWITNESS_DRIVER=chromedp  browser driver: gorod (auto-downloads Chromium) | chromedp (needs system Chrome)"
  echo ""
  echo -e "${BOLD}Notes:${NC}"
  echo "  Run as root (sudo) for SYN scanning, OS detection, and UDP scanning."
  echo "  Without root, naabu falls back to connect scans and UDP scanning is skipped."
  echo "  --external tunes rate/timing/retries but does not add scope safeguards — confirm the target"
  echo "  IPs are in-scope and the engagement's ROE permits active scanning before running it."
  echo ""
}

main() {
  echo -e "${CYAN}${BOLD}"
  echo "  internal_discovery.sh — Internal Network Discovery"
  echo -e "${NC}${DIM}  naabu -> nmap -A -> nmap UDP -> httpx -> gowitness -> nuclei${NC}"
  echo -e "${DIM}  For authorized internal engagements only.${NC}"
  echo ""

  local run_install=0
  local target_arg=""

  # Manual parser (not getopts — getopts can't do long options like
  # --top-ports) supporting both short and long forms.
  while [ $# -gt 0 ]; do
    case "$1" in
      -n|--name)
        [ $# -ge 2 ] || { err "Option $1 requires an argument."; usage; exit 1; }
        PROJECT_NAME="$2"; shift 2 ;;
      -i|--targets)
        [ $# -ge 2 ] || { err "Option $1 requires an argument."; usage; exit 1; }
        target_arg="$2"; shift 2 ;;
      -e|--install)
        run_install=1; shift ;;
      --all-ports)
        TCP_TOP_PORTS=""; PORT_SCOPE_EXPLICIT=1; shift ;;
      --top-ports)
        [ $# -ge 2 ] || { err "Option $1 requires an argument."; usage; exit 1; }
        [[ "$2" =~ ^[0-9]+$ ]] || { err "--top-ports needs a number (e.g. --top-ports 1000), got: $2"; usage; exit 1; }
        TCP_TOP_PORTS="$2"; PORT_SCOPE_EXPLICIT=1; shift 2 ;;
      --no-ping)
        SKIP_HOST_DISCOVERY=1; shift ;;
      --internal)
        SCAN_PROFILE="internal"; shift ;;
      --external)
        SCAN_PROFILE="external"; shift ;;
      -h|--help)
        usage; exit 0 ;;
      *)
        err "Unknown option: $1"; usage; exit 1 ;;
    esac
  done

  if [ "$run_install" -eq 1 ]; then
    install_deps_local
    exit 0
  fi

  if [ -z "$PROJECT_NAME" ] || [ -z "$target_arg" ]; then
    err "Both -n <project-name> and -i <targets> are required."
    usage
    exit 1
  fi

  apply_scan_profile

  preflight_check || { err "Pre-flight failed. Run: $0 -e"; exit 1; }

  # OUTPUT_DIR/hosts must exist before resolve_targets can stage a synthetic
  # target file, so create the project skeleton first.
  setup_project
  resolve_targets "$target_arg" || exit 1

  phase1_host_discovery
  phase2_port_scan
  phase3_nmap_deep
  phase4_udp_scan
  phase5_httpx
  phase6_gowitness
  phase7_nuclei
  generate_summary

  echo ""
  ok "${BOLD}Done.${NC} Results → $OUTPUT_DIR/"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then main "$@"; fi
