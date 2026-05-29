#!/usr/bin/env bash
# singbox-monitor — health-check + self-heal for sing-box
#
# Tiered escalation (most likely → least invasive remediation):
#   A. service down OR SOCKS port not listening   → restart sing-box
#   B. loopback proxy check fails                 → restart sing-box; if still bad → networkd + reboot
#   C. hairpin proxy check fails (if enabled)     → restart networkd; if still bad → reboot
#   D. server cannot reach the internet           → restart networkd; if still bad → reboot
#
# If sing-box isn't installed, tiers A/B/C are skipped — only tier D runs,
# so the monitor still acts as a network watchdog for the host.
#
# Hairpin = test through the server's PUBLIC IP. Verified at install time by
# checking sing-box's journal for an inbound connection logged with the
# public IP as the source; if AWS short-circuits the request internally
# (no round-trip), the check is disabled to avoid false positives.
#
# Reboot is rate-limited.
#
# Daily security upgrade:
#   When sing-box is installed, a separate systemd timer fires every day at
#   05:00 UTC and auto-upgrades to the latest stable sing-box release if
#   newer than installed. The new binary is validated against the running
#   config BEFORE swap; if the service fails to come up or the loopback
#   proxy test breaks after restart, the previous binary is restored.
#
# Usage:
#   sudo bash singbox-monitor.sh install         # install + auto-detect hairpin
#   sudo bash singbox-monitor.sh check           # one health-check pass
#   sudo bash singbox-monitor.sh upgrade         # one-shot upgrade attempt
#   sudo bash singbox-monitor.sh verify-hairpin  # re-run hairpin self-test
#   sudo bash singbox-monitor.sh status          # timer state + recent log
#   sudo bash singbox-monitor.sh uninstall

set -euo pipefail

# ---------- Configuration ----------
SINGBOX_CREDENTIALS="/etc/sing-box/credentials"
SINGBOX_SERVICE_FILE="/etc/systemd/system/sing-box.service"
NETIF="${MONITOR_NETIF:-ens5}"
DISABLE_HAIRPIN="${MONITOR_DISABLE_HAIRPIN:-0}"
PROXY_TEST_URL="https://api.ipify.org"
EXT_TEST_URL="https://1.1.1.1/cdn-cgi/trace"
CURL_TIMEOUT=8

STATE_DIR="/var/lib/singbox-monitor"
REBOOT_LOG="$STATE_DIR/reboots.log"
ACTION_LOG="$STATE_DIR/actions.log"
HAIRPIN_FLAG="$STATE_DIR/hairpin-enabled"
PUBIP_CACHE="$STATE_DIR/public-ip"
MAX_REBOOTS_PER_DAY=4
MIN_REBOOT_INTERVAL_SEC=1800

SCRIPT_PATH="/usr/local/bin/singbox-monitor.sh"
# Canonical location to re-fetch this script from when it's run via
# `bash -c "$(curl ...)"` / a pipe and therefore has no on-disk source to copy.
SELF_URL="${SINGBOX_MONITOR_URL:-https://raw.githubusercontent.com/olivcraw/myscripts/main/singbox-monitor.sh}"
SVC_FILE="/etc/systemd/system/singbox-monitor.service"
TIMER_FILE="/etc/systemd/system/singbox-monitor.timer"
TIMER_INTERVAL="1min"

# Daily auto-upgrade for sing-box (security patching)
UPGRADE_SVC_FILE="/etc/systemd/system/singbox-monitor-upgrade.service"
UPGRADE_TIMER_FILE="/etc/systemd/system/singbox-monitor-upgrade.timer"
UPGRADE_SCHEDULE="*-*-* 05:00:00 UTC"   # daily at 05:00 UTC

SINGBOX_BIN="/usr/local/bin/sing-box"
SINGBOX_BIN_PREV="/usr/local/bin/sing-box.previous"
SINGBOX_CONFIG="/etc/sing-box/config.json"
LOCK_FILE_REL="lock"
# -----------------------------------

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $*"; _audit "INFO" "$*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; _audit "WARN" "$*"; }
err()  { echo -e "${RED}[x]${NC} $*" >&2; _audit "ERR " "$*"; }
info() { echo -e "${BLUE}[i]${NC} $*"; }
_audit() { local lvl="$1"; shift; echo "[$(date '+%F %T')] $lvl $*" >> "$ACTION_LOG" 2>/dev/null || true; }

require_root() {
    [[ $EUID -eq 0 ]] || { err "Must run as root."; exit 1; }
}

ensure_state_dir() {
    mkdir -p "$STATE_DIR"
    chmod 700 "$STATE_DIR"
}

# Is sing-box actually installed? Checks for both the systemd unit and the
# credentials file the monitor needs. Without this guard the escalation
# chain would interpret "service missing" as a failure and reboot.
singbox_is_installed() {
    systemctl cat sing-box.service >/dev/null 2>&1 && [[ -r "$SINGBOX_CREDENTIALS" ]]
}

# Acquire a PID lock so the per-minute health check and the daily upgrader
# don't run remediation actions concurrently. Returns 1 if held.
acquire_lock_or_skip() {
    local lock="$STATE_DIR/$LOCK_FILE_REL"
    if [[ -f "$lock" ]]; then
        local pid
        pid=$(cat "$lock" 2>/dev/null)
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            return 1
        fi
    fi
    echo $$ > "$lock"
    trap 'rm -f "'"$lock"'"' EXIT
    return 0
}

# Read SOCKS port from credentials, fall back to 8443
socks_port() {
    if [[ -r "$SINGBOX_CREDENTIALS" ]]; then
        # shellcheck disable=SC1090
        ( source "$SINGBOX_CREDENTIALS"; echo "${SOCKS_PORT:-${PORT:-8443}}" )
    else
        echo 8443
    fi
}

# ----------------------------------------------------------------------
# IMDS — get public IP
# ----------------------------------------------------------------------

get_public_ip_from_imds() {
    local token ip
    token=$(curl -fsS -X PUT --max-time 2 \
        -H "X-aws-ec2-metadata-token-ttl-seconds: 60" \
        "http://169.254.169.254/latest/api/token" 2>/dev/null || true)
    if [[ -n "$token" ]]; then
        ip=$(curl -fsS --max-time 2 \
            -H "X-aws-ec2-metadata-token: $token" \
            "http://169.254.169.254/latest/meta-data/public-ipv4" 2>/dev/null || true)
    fi
    if [[ -z "${ip:-}" ]]; then
        ip=$(curl -fsS --max-time 2 \
            "http://169.254.169.254/latest/meta-data/public-ipv4" 2>/dev/null || true)
    fi
    [[ "${ip:-}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && echo "$ip"
}

refresh_public_ip() {
    local fresh
    fresh=$(get_public_ip_from_imds || true)
    if [[ -n "${fresh:-}" ]]; then
        echo "$fresh" > "$PUBIP_CACHE"
        echo "$fresh"
        return 0
    fi
    if [[ -f "$PUBIP_CACHE" ]]; then
        cat "$PUBIP_CACHE"
        return 0
    fi
    return 1
}

# ----------------------------------------------------------------------
# Health checks
# ----------------------------------------------------------------------

check_service_up() {
    systemctl is-active --quiet sing-box
}

check_listening() {
    local port
    port=$(socks_port)
    ss -tln 2>/dev/null | awk '{print $4}' | grep -qE ":${port}\$"
}

# Run a SOCKS5 + auth proxy test through a given host.
# Auth is passed via a tempfile so the password never appears in ps output.
proxy_test_via() {
    local addr="$1"
    [[ -r "$SINGBOX_CREDENTIALS" ]] || return 2
    local USERNAME PASSWORD SOCKS_PORT PORT
    # shellcheck disable=SC1090
    source "$SINGBOX_CREDENTIALS"
    local port="${SOCKS_PORT:-${PORT:-8443}}"

    local cfg
    cfg=$(mktemp)
    chmod 600 "$cfg"
    printf 'proxy-user = "%s:%s"\n' "$USERNAME" "$PASSWORD" > "$cfg"

    local out rc
    out=$(curl --max-time "$CURL_TIMEOUT" --socks5 "${addr}:${port}" \
                -K "$cfg" -fsS "$PROXY_TEST_URL" 2>&1)
    rc=$?
    rm -f "$cfg"
    [[ $rc -eq 0 ]] || return 1
    [[ "$out" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
    return 0
}

check_loopback_proxy() {
    proxy_test_via "127.0.0.1"
}

check_hairpin_proxy() {
    local pub
    pub=$(refresh_public_ip) || return 2
    proxy_test_via "$pub"
}

check_outbound_internet() {
    curl --max-time "$CURL_TIMEOUT" -fsS "$EXT_TEST_URL" >/dev/null 2>&1
}

# ----------------------------------------------------------------------
# Hairpin self-test: must observe sing-box actually logging an inbound
# connection from the public IP. If we can curl through the public IP but
# sing-box never saw the request as coming from there, AWS short-circuited
# the path and the check provides no benefit over loopback — disable it.
#
# sing-box log line shape:
#   ... INFO inbound/socks[socks-in]: inbound connection from <IP>:<port>
# ----------------------------------------------------------------------

verify_hairpin() {
    require_root
    ensure_state_dir

    if [[ "$DISABLE_HAIRPIN" == "1" ]]; then
        warn "Hairpin disabled via MONITOR_DISABLE_HAIRPIN=1"
        rm -f "$HAIRPIN_FLAG"
        return 1
    fi

    local pub
    pub=$(refresh_public_ip) || { warn "No public IP from IMDS; hairpin disabled."; rm -f "$HAIRPIN_FLAG"; return 1; }
    info "Public IP: $pub"

    info "Running hairpin probe..."
    local since
    since=$(date '+%Y-%m-%d %H:%M:%S')
    sleep 1

    if ! proxy_test_via "$pub"; then
        warn "Hairpin curl through ${pub} FAILED — disabling hairpin check."
        rm -f "$HAIRPIN_FLAG"
        return 1
    fi
    info "Hairpin curl succeeded — checking sing-box journal for source=${pub}..."
    sleep 2  # journald flush

    local hits
    hits=$(journalctl -u sing-box --since "$since" --no-pager 2>/dev/null \
        | grep -c "inbound connection from ${pub}:" || true)

    if [[ "$hits" -gt 0 ]]; then
        echo "$pub" > "$HAIRPIN_FLAG"
        log "Hairpin VERIFIED — sing-box saw inbound from ${pub} (${hits} log entry/entries). Hairpin check ENABLED."
        return 0
    else
        warn "Hairpin curl worked but sing-box didn't log an inbound from ${pub}."
        warn "AWS likely short-circuited the request — hairpin check DISABLED (would be no better than loopback)."
        rm -f "$HAIRPIN_FLAG"
        return 1
    fi
}

hairpin_is_enabled() {
    [[ -f "$HAIRPIN_FLAG" ]]
}

# ----------------------------------------------------------------------
# Auto-upgrade: pull latest stable sing-box if newer than installed.
# Safety: validate new binary against current config BEFORE swap, keep
# previous binary, rollback if the service fails to come up.
# ----------------------------------------------------------------------

singbox_installed_version() {
    [[ -x "$SINGBOX_BIN" ]] || return 1
    local out
    out=$("$SINGBOX_BIN" version 2>/dev/null) || return 1
    # Match "sing-box version X.Y.Z" using bash built-in regex (no pipeline
    # → no SIGPIPE → safe under set -o pipefail).
    [[ "$out" =~ ^sing-box[[:space:]]+version[[:space:]]+([^[:space:]]+) ]] || return 1
    echo "${BASH_REMATCH[1]}"
}

# GitHub's /releases/latest returns the most recent non-prerelease, so
# this is "latest stable" by definition.
# NOTE: we DO NOT use a pipeline to extract the tag — when `grep -m1` or
# similar closes its stdin early, the upstream writer gets SIGPIPE and
# with `set -o pipefail` the whole function returns non-zero even though
# we got the data. Use bash regex on the buffered response instead.
singbox_latest_stable_version() {
    local resp
    resp=$(curl -fsSL --max-time 10 \
        https://api.github.com/repos/SagerNet/sing-box/releases/latest 2>/dev/null) || return 1
    [[ -n "$resp" ]] || return 1
    [[ "$resp" =~ \"tag_name\":[[:space:]]*\"v?([^\"]+)\" ]] || return 1
    echo "${BASH_REMATCH[1]}"
}

# Returns 0 (true) iff $1 strictly less than $2 in semver order.
semver_lt() {
    [[ "$1" != "$2" ]] && [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" == "$1" ]]
}

# Arch suffix used in sing-box release tarball names.
release_arch() {
    case "$(uname -m)" in
        x86_64)  echo "amd64" ;;
        aarch64) echo "arm64" ;;
        armv7l)  echo "armv7" ;;
        *)       return 1 ;;
    esac
}

upgrade_singbox() {
    require_root
    ensure_state_dir

    if ! acquire_lock_or_skip; then
        warn "Another singbox-monitor operation is in progress; skipping upgrade."
        return 0
    fi

    if ! singbox_is_installed; then
        info "sing-box not installed — skipping upgrade."
        return 0
    fi

    local cur new arch
    cur=$(singbox_installed_version) || { err "Could not read installed sing-box version."; return 1; }
    new=$(singbox_latest_stable_version) || { warn "Could not fetch latest version from GitHub (network issue?)."; return 1; }
    arch=$(release_arch) || { err "Unsupported architecture: $(uname -m)"; return 1; }

    if [[ -z "$new" ]]; then
        warn "Empty version from GitHub API. Skipping."
        return 1
    fi

    log "sing-box installed=${cur}  latest_stable=${new}"

    if ! semver_lt "$cur" "$new"; then
        log "Already at latest stable. No upgrade needed."
        return 0
    fi

    log "New stable available — upgrading ${cur} → ${new}"

    local tmp url subdir
    tmp=$(mktemp -d)
    url="https://github.com/SagerNet/sing-box/releases/download/v${new}/sing-box-${new}-linux-${arch}.tar.gz"
    if ! curl -fsSL --max-time 60 -o "$tmp/sb.tar.gz" "$url"; then
        err "Download failed: $url"
        rm -rf "$tmp"
        return 1
    fi
    tar -xzf "$tmp/sb.tar.gz" -C "$tmp"
    subdir="sing-box-${new}-linux-${arch}"
    if [[ ! -x "$tmp/$subdir/sing-box" ]]; then
        err "Binary not found at $tmp/$subdir/sing-box"
        rm -rf "$tmp"
        return 1
    fi

    # Validate the new binary can parse the live config BEFORE swapping in.
    if [[ -f "$SINGBOX_CONFIG" ]]; then
        if ! "$tmp/$subdir/sing-box" check -c "$SINGBOX_CONFIG" >/dev/null 2>&1; then
            err "sing-box v${new} cannot parse current config — aborting upgrade."
            rm -rf "$tmp"
            return 1
        fi
        log "Config compatibility check passed against v${new}"
    fi

    # Swap: backup current binary, install new, restart service
    cp -a "$SINGBOX_BIN" "$SINGBOX_BIN_PREV"
    install -m 755 "$tmp/$subdir/sing-box" "$SINGBOX_BIN"
    rm -rf "$tmp"
    log "Binary swapped; restarting sing-box.service..."
    systemctl restart sing-box

    sleep 3
    if ! systemctl is-active --quiet sing-box; then
        err "sing-box did not start after upgrade — rolling back to ${cur}"
        install -m 755 "$SINGBOX_BIN_PREV" "$SINGBOX_BIN"
        systemctl restart sing-box || true
        return 1
    fi

    # Functional check beyond just "active": loopback proxy must work
    if check_loopback_proxy 2>/dev/null; then
        log "Upgrade SUCCESS — sing-box v${new} is running and serving"
        echo "$(date '+%F %T') ${cur} -> ${new}" >> "$STATE_DIR/upgrades.log"
        return 0
    else
        err "Loopback proxy check failed after upgrade — rolling back to ${cur}"
        install -m 755 "$SINGBOX_BIN_PREV" "$SINGBOX_BIN"
        systemctl restart sing-box || true
        return 1
    fi
}

# ----------------------------------------------------------------------
# Reboot rate-limit
# ----------------------------------------------------------------------

count_reboots_today() {
    [[ -f "$REBOOT_LOG" ]] || { echo 0; return; }
    grep -c "^$(date +%F) " "$REBOOT_LOG" 2>/dev/null || echo 0
}

last_reboot_age_sec() {
    [[ -f "$REBOOT_LOG" ]] || { echo 999999; return; }
    local last
    last=$(tail -1 "$REBOOT_LOG" 2>/dev/null)
    [[ -n "$last" ]] || { echo 999999; return; }
    echo $(( $(date +%s) - $(date -d "$last" +%s 2>/dev/null || echo 0) ))
}

can_reboot() {
    local count age
    count=$(count_reboots_today)
    age=$(last_reboot_age_sec)
    if [[ $count -ge $MAX_REBOOTS_PER_DAY ]]; then
        err "Reboot rate-limit hit (${count}/${MAX_REBOOTS_PER_DAY} today). Refusing."
        return 1
    fi
    if [[ $age -lt $MIN_REBOOT_INTERVAL_SEC ]]; then
        err "Last reboot was ${age}s ago (< ${MIN_REBOOT_INTERVAL_SEC}s). Refusing."
        return 1
    fi
    return 0
}

# ----------------------------------------------------------------------
# Remediation
# ----------------------------------------------------------------------

action_restart_singbox() {
    log "Action: restarting sing-box.service"
    systemctl restart sing-box || true
    sleep 3
}

action_restart_network() {
    log "Action: restarting systemd-networkd + reconfiguring $NETIF"
    systemctl restart systemd-networkd || true
    networkctl reconfigure "$NETIF" 2>/dev/null || true
    sleep 8
}

action_reboot() {
    if ! can_reboot; then return 1; fi
    warn "Action: REBOOTING server (last-resort recovery)"
    date '+%F %T' >> "$REBOOT_LOG"
    sync
    sleep 2
    /sbin/reboot
}

# ----------------------------------------------------------------------
# Check + escalate
# ----------------------------------------------------------------------

run_check() {
    require_root
    ensure_state_dir

    if ! acquire_lock_or_skip; then
        # Upgrade probably mid-flight; let it finish.
        return 0
    fi

    # sing-box-specific checks (A, B, C) only when sing-box is installed.
    # Tier D (outbound watchdog) runs unconditionally.
    if singbox_is_installed; then
        # Tier A — process & socket
        if ! check_service_up; then
            warn "sing-box.service not active"
            action_restart_singbox
            if ! check_service_up; then
                err "sing-box still not active after restart"
                action_restart_network
                check_service_up || action_reboot
            fi
            return 0
        fi
        if ! check_listening; then
            warn "SOCKS port $(socks_port) not listening"
            action_restart_singbox
            return 0
        fi

        # Tier B — loopback proxy (sing-box actually serving)
        if ! check_loopback_proxy; then
            warn "Loopback proxy check failed (process up but not serving)"
            action_restart_singbox
            if ! check_loopback_proxy; then
                err "Loopback STILL failing after restart"
                action_restart_network
                check_loopback_proxy || action_reboot
            fi
            return 0
        fi

        # Tier C — hairpin (catches the AWS-side inbound failure mode)
        if hairpin_is_enabled; then
            if ! check_hairpin_proxy; then
                warn "Hairpin check FAILED (loopback OK, public path BROKEN)"
                action_restart_network
                if ! check_hairpin_proxy; then
                    err "Hairpin STILL broken after networkd restart — rebooting"
                    action_reboot
                else
                    log "Hairpin restored after networkd restart"
                fi
                return 0
            fi
        fi
    fi

    # Tier D — outbound reachability (always run; also the watchdog when
    # sing-box isn't installed)
    if ! check_outbound_internet; then
        warn "Server cannot reach the internet"
        action_restart_network
        if ! check_outbound_internet; then
            err "Outbound STILL broken after networkd restart — rebooting"
            action_reboot
        else
            log "Outbound restored after networkd restart"
        fi
        return 0
    fi

    echo "OK $(date '+%F %T')" > "$STATE_DIR/last-ok"
}

# ----------------------------------------------------------------------
# Install / uninstall
# ----------------------------------------------------------------------

install_monitor() {
    require_root
    ensure_state_dir

    for cmd in curl ss systemctl journalctl networkctl; do
        command -v "$cmd" >/dev/null 2>&1 || { err "Missing dependency: $cmd"; exit 1; }
    done

    if ! singbox_is_installed; then
        warn "sing-box is not installed — monitor will run as a network watchdog only"
        warn "(skipping tiers A/B/C; tier D outbound check still active)."
    fi

    # Persist this script to disk so the systemd units can run it. When invoked
    # as a normal file (`sudo bash singbox-monitor.sh install`) $0 is a readable
    # path we can copy. When invoked via `bash -c "$(curl ...)"` or a pipe, $0 is
    # not a real file (e.g. "--" or "bash"), so re-download from SELF_URL instead.
    if [[ -f "$0" && -r "$0" ]]; then
        install -m 755 "$0" "$SCRIPT_PATH"
        log "Script installed at $SCRIPT_PATH (copied from $0)"
    else
        log "No on-disk source (piped run) — fetching script from $SELF_URL"
        local tmp_self
        tmp_self=$(mktemp)
        if ! curl -fsSL --max-time "$CURL_TIMEOUT" "$SELF_URL" -o "$tmp_self"; then
            err "Failed to download script from $SELF_URL"
            err "Set SINGBOX_MONITOR_URL to a reachable raw URL, or run from a local file."
            rm -f "$tmp_self"
            exit 1
        fi
        # Sanity check: must look like this script, not an HTML 404 page.
        if ! grep -q 'singbox-monitor' "$tmp_self"; then
            err "Downloaded file doesn't look like singbox-monitor.sh (got a 404/HTML page?)."
            rm -f "$tmp_self"
            exit 1
        fi
        install -m 755 "$tmp_self" "$SCRIPT_PATH"
        rm -f "$tmp_self"
        log "Script installed at $SCRIPT_PATH (downloaded from $SELF_URL)"
    fi

    cat > "$SVC_FILE" <<EOF
[Unit]
Description=singbox-monitor — health check and self-heal
After=network-online.target sing-box.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/env bash $SCRIPT_PATH check
SuccessExitStatus=0 1
EOF

    cat > "$TIMER_FILE" <<EOF
[Unit]
Description=singbox-monitor periodic check

[Timer]
OnBootSec=2min
OnUnitActiveSec=$TIMER_INTERVAL
AccuracySec=15s
Unit=singbox-monitor.service

[Install]
WantedBy=timers.target
EOF

    # Daily sing-box auto-upgrade (security patching)
    cat > "$UPGRADE_SVC_FILE" <<EOF
[Unit]
Description=singbox-monitor — daily sing-box auto-upgrade (security patching)
After=network-online.target sing-box.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/env bash $SCRIPT_PATH upgrade
SuccessExitStatus=0 1
EOF

    cat > "$UPGRADE_TIMER_FILE" <<EOF
[Unit]
Description=singbox-monitor daily upgrade @ 05:00 UTC

[Timer]
OnCalendar=$UPGRADE_SCHEDULE
Persistent=true
RandomizedDelaySec=5min
Unit=singbox-monitor-upgrade.service

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable --now singbox-monitor.timer
    systemctl enable --now singbox-monitor-upgrade.timer
    log "Health-check timer enabled — runs every $TIMER_INTERVAL"
    log "Auto-upgrade timer enabled — fires daily @ $UPGRADE_SCHEDULE"

    echo ""
    info "Running hairpin self-test..."
    if verify_hairpin; then
        info "Hairpin mode: ENABLED (catches AWS-side inbound failures)"
    else
        info "Hairpin mode: DISABLED (will use loopback + outbound checks only)"
    fi

    echo ""
    info "Force check:    sudo bash $SCRIPT_PATH check"
    info "Status / logs:  sudo bash $SCRIPT_PATH status"
    info "Re-verify hp:   sudo bash $SCRIPT_PATH verify-hairpin"
}

uninstall_monitor() {
    require_root
    log "Stopping & disabling timers..."
    systemctl stop    singbox-monitor.timer         singbox-monitor-upgrade.timer 2>/dev/null || true
    systemctl disable singbox-monitor.timer         singbox-monitor-upgrade.timer 2>/dev/null || true
    systemctl stop    singbox-monitor.service       singbox-monitor-upgrade.service 2>/dev/null || true

    log "Removing systemd units..."
    rm -f "$TIMER_FILE" "$SVC_FILE" "$UPGRADE_TIMER_FILE" "$UPGRADE_SVC_FILE"
    systemctl daemon-reload
    systemctl reset-failed singbox-monitor.service singbox-monitor.timer \
        singbox-monitor-upgrade.service singbox-monitor-upgrade.timer 2>/dev/null || true

    log "Removing script..."
    rm -f "$SCRIPT_PATH"

    info "Keeping state dir ($STATE_DIR) — contains reboot history / action log."
    info "Remove it manually with: sudo rm -rf $STATE_DIR"
    log "Uninstalled."
}

show_status() {
    echo "=== health-check timer ==="
    systemctl status singbox-monitor.timer --no-pager 2>&1 | head -8 || true
    echo ""
    echo "=== auto-upgrade timer ==="
    systemctl list-timers singbox-monitor-upgrade.timer --no-pager 2>&1 | head -3 || true
    if [[ -f "$STATE_DIR/upgrades.log" ]]; then
        echo "Past upgrades:"
        tail -5 "$STATE_DIR/upgrades.log" | sed 's/^/  /'
    else
        echo "Past upgrades: (none recorded)"
    fi
    if [[ -x "$SINGBOX_BIN" ]]; then
        echo "Current sing-box: $(singbox_installed_version 2>/dev/null || echo unknown)"
    fi
    echo ""
    echo "=== sing-box target ==="
    if singbox_is_installed; then
        echo "sing-box installed — full tiered checks (A/B/C/D) + daily upgrade active."
    else
        echo "sing-box NOT installed — watchdog mode (only tier D outbound check)."
    fi
    echo ""
    echo "=== mode ==="
    if hairpin_is_enabled; then
        echo "Hairpin: ENABLED (target: $(cat "$HAIRPIN_FLAG" 2>/dev/null))"
    else
        echo "Hairpin: DISABLED (loopback + outbound only)"
    fi
    if [[ -f "$PUBIP_CACHE" ]]; then
        echo "Cached public IP: $(cat "$PUBIP_CACHE")"
    fi
    echo ""
    echo "=== last successful check ==="
    cat "$STATE_DIR/last-ok" 2>/dev/null || echo "(none)"
    echo ""
    echo "=== last 20 action log entries ==="
    tail -20 "$ACTION_LOG" 2>/dev/null || echo "(no actions logged yet)"
    echo ""
    echo "=== monitor-triggered reboots ==="
    if [[ -f "$REBOOT_LOG" ]]; then
        cat "$REBOOT_LOG"
        echo "(today: $(count_reboots_today)/${MAX_REBOOTS_PER_DAY})"
    else
        echo "(none)"
    fi
}

usage() {
    cat <<EOF
singbox-monitor — health-check + self-heal + auto-upgrade for sing-box

Usage: sudo bash $0 <command>

Commands:
  install         Install script + TWO systemd timers:
                    - health check every ${TIMER_INTERVAL}
                    - sing-box auto-upgrade daily @ ${UPGRADE_SCHEDULE}
                  Then auto-detect whether hairpin check is usable.
  check           Run one health-check pass (used by the check timer).
  upgrade         Check for newer stable sing-box; if found, validate it
                  against the live config and swap with rollback on failure.
                  (Used by the upgrade timer.)
  verify-hairpin  Re-run the hairpin self-test (enable/disable accordingly).
  status          Show timer state, mode, upgrade history, recent actions.
  uninstall       Remove timers, services and script (keeps state dir).
  help            This message.

Environment overrides:
  MONITOR_NETIF             primary interface  (default: ens5)
  MONITOR_DISABLE_HAIRPIN   set to 1 to force-disable hairpin check

Escalation per check:
  A. service down / not listening    → restart sing-box
  B. loopback proxy fails            → restart sing-box → networkd → reboot
  C. hairpin fails (if enabled)      → restart networkd → reboot
  D. no outbound internet            → restart networkd → reboot

Reboot rate-limit: ${MAX_REBOOTS_PER_DAY}/day, ≥${MIN_REBOOT_INTERVAL_SEC}s apart.

Logs:
  Actions:  $ACTION_LOG
  Reboots:  $REBOOT_LOG
  Journal:  journalctl -u singbox-monitor.service
EOF
}

main() {
    case "${1:-help}" in
        install)         install_monitor ;;
        uninstall|remove) uninstall_monitor ;;
        check)           run_check ;;
        upgrade)         upgrade_singbox ;;
        verify-hairpin)  verify_hairpin ;;
        status)          show_status ;;
        help|-h|--help)  usage ;;
        *) err "Unknown command: $1"; echo; usage; exit 1 ;;
    esac
}

main "$@"
