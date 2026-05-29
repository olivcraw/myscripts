#!/usr/bin/env bash
# gost-monitor — health-check + self-heal for the gost SOCKS5 service
#
# Tiered escalation (most likely → least invasive remediation):
#   A. service down OR port not listening      → restart gost
#   B. loopback proxy check fails              → restart gost; if still bad → networkd + reboot
#   C. hairpin proxy check fails (if enabled)  → restart networkd; if still bad → reboot
#   D. server cannot reach the internet        → restart networkd; if still bad → reboot
#
# If gost isn't installed, tiers A/B/C are skipped — only tier D runs, so the
# monitor still acts as a network watchdog for the host.
#
# Hairpin = test through the server's PUBLIC IP. Verified at install time by
# checking gost's journal for a connection logged with the public IP as the
# source; if AWS short-circuits the request internally (no round-trip), the
# check is disabled to avoid false positives.
#
# Reboot is rate-limited.
#
# Usage:
#   sudo bash gost-monitor.sh install         # install + auto-detect hairpin
#   sudo bash gost-monitor.sh check           # one health-check pass
#   sudo bash gost-monitor.sh verify-hairpin  # re-run hairpin self-test
#   sudo bash gost-monitor.sh status          # timer state + recent log
#   sudo bash gost-monitor.sh uninstall

set -euo pipefail

# ---------- Configuration ----------
GOST_CREDENTIALS="/etc/gost/credentials"
NETIF="${MONITOR_NETIF:-ens5}"
DISABLE_HAIRPIN="${MONITOR_DISABLE_HAIRPIN:-0}"
PROXY_TEST_URL="https://api.ipify.org"
EXT_TEST_URL="https://1.1.1.1/cdn-cgi/trace"
CURL_TIMEOUT=8

STATE_DIR="/var/lib/gost-monitor"
REBOOT_LOG="$STATE_DIR/reboots.log"
ACTION_LOG="$STATE_DIR/actions.log"
HAIRPIN_FLAG="$STATE_DIR/hairpin-enabled"
PUBIP_CACHE="$STATE_DIR/public-ip"
MAX_REBOOTS_PER_DAY=4
MIN_REBOOT_INTERVAL_SEC=1800

SCRIPT_PATH="/usr/local/bin/gost-monitor.sh"
SVC_FILE="/etc/systemd/system/gost-monitor.service"
TIMER_FILE="/etc/systemd/system/gost-monitor.timer"
TIMER_INTERVAL="1min"
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

# Is gost actually installed? Checks for both the systemd unit and the
# credentials file the monitor needs. Without this guard the escalation
# chain would interpret "gost unit missing" as a failure and reboot.
gost_is_installed() {
    systemctl cat gost.service >/dev/null 2>&1 && [[ -r "$GOST_CREDENTIALS" ]]
}

# ----------------------------------------------------------------------
# IMDS — get public IP
# ----------------------------------------------------------------------

get_public_ip_from_imds() {
    local token ip
    # IMDSv2 first
    token=$(curl -fsS -X PUT --max-time 2 \
        -H "X-aws-ec2-metadata-token-ttl-seconds: 60" \
        "http://169.254.169.254/latest/api/token" 2>/dev/null || true)
    if [[ -n "$token" ]]; then
        ip=$(curl -fsS --max-time 2 \
            -H "X-aws-ec2-metadata-token: $token" \
            "http://169.254.169.254/latest/meta-data/public-ipv4" 2>/dev/null || true)
    fi
    # IMDSv1 fallback
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
    systemctl is-active --quiet gost
}

check_listening() {
    ss -tln 2>/dev/null | awk '{print $4}' | grep -qE ':8443$'
}

# Run a SOCKS5 + auth proxy test through a given host:port.
# Auth is passed via a tempfile so the password never appears in ps output.
proxy_test_via() {
    local addr="$1"
    [[ -r "$GOST_CREDENTIALS" ]] || return 2
    local USERNAME PASSWORD PORT
    # shellcheck disable=SC1090
    source "$GOST_CREDENTIALS"
    PORT="${PORT:-8443}"

    local cfg
    cfg=$(mktemp)
    chmod 600 "$cfg"
    printf 'proxy-user = "%s:%s"\n' "$USERNAME" "$PASSWORD" > "$cfg"

    local out rc
    out=$(curl --max-time "$CURL_TIMEOUT" --socks5 "${addr}:${PORT}" \
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
# Hairpin self-test: must observe gost actually logging a connection from
# the public IP. If we can curl through the public IP but gost never saw
# the request as coming from there, AWS short-circuited the path and the
# check provides no benefit over loopback — disable it.
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
    # Allow a 2-second window before the probe to absorb clock skew
    sleep 1

    if ! proxy_test_via "$pub"; then
        warn "Hairpin curl through ${pub}:8443 FAILED — disabling hairpin check."
        rm -f "$HAIRPIN_FLAG"
        return 1
    fi
    info "Hairpin curl succeeded — checking gost journal for source=${pub}..."
    sleep 2  # journald flush

    local hits
    hits=$(journalctl -u gost --since "$since" --no-pager 2>/dev/null \
        | grep -c "\"client\":\"${pub}:" || true)

    if [[ "$hits" -gt 0 ]]; then
        echo "$pub" > "$HAIRPIN_FLAG"
        log "Hairpin VERIFIED — gost saw connection from ${pub} (${hits} log entry/entries). Hairpin check ENABLED."
        return 0
    else
        warn "Hairpin curl worked but gost didn't log it from ${pub}."
        warn "AWS likely short-circuited the request — hairpin check DISABLED (would be no better than loopback)."
        rm -f "$HAIRPIN_FLAG"
        return 1
    fi
}

hairpin_is_enabled() {
    [[ -f "$HAIRPIN_FLAG" ]]
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

action_restart_gost() {
    log "Action: restarting gost.service"
    systemctl restart gost || true
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

    # Gost-specific checks (A, B, C) only when gost is installed.
    # Tier D (outbound watchdog) runs unconditionally.
    if gost_is_installed; then
        # Tier A — process & socket
        if ! check_service_up; then
            warn "gost.service not active"
            action_restart_gost
            if ! check_service_up; then
                err "gost still not active after restart"
                action_restart_network
                check_service_up || action_reboot
            fi
            return 0
        fi
        if ! check_listening; then
            warn "Port 8443 not listening"
            action_restart_gost
            return 0
        fi

        # Tier B — loopback proxy (gost actually serving)
        if ! check_loopback_proxy; then
            warn "Loopback proxy check failed (process up but not serving)"
            action_restart_gost
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
    # gost isn't installed)
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

    # All checks passed
    echo "OK $(date '+%F %T')" > "$STATE_DIR/last-ok"
}

# ----------------------------------------------------------------------
# Install / uninstall
# ----------------------------------------------------------------------

install_monitor() {
    require_root
    ensure_state_dir

    # Check dependencies
    for cmd in curl ss systemctl journalctl networkctl; do
        command -v "$cmd" >/dev/null 2>&1 || { err "Missing dependency: $cmd"; exit 1; }
    done

    if ! gost_is_installed; then
        warn "gost is not installed — monitor will run as a network watchdog only"
        warn "(skipping tiers A/B/C; tier D outbound check still active)."
    fi

    install -m 755 "$0" "$SCRIPT_PATH"
    log "Script installed at $SCRIPT_PATH"

    cat > "$SVC_FILE" <<EOF
[Unit]
Description=gost-monitor — health check and self-heal
After=network-online.target gost.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/env bash $SCRIPT_PATH check
SuccessExitStatus=0 1
EOF

    cat > "$TIMER_FILE" <<EOF
[Unit]
Description=gost-monitor periodic check

[Timer]
OnBootSec=2min
OnUnitActiveSec=$TIMER_INTERVAL
AccuracySec=15s
Unit=gost-monitor.service

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable --now gost-monitor.timer
    log "Timer enabled — runs every $TIMER_INTERVAL"

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
    log "Stopping & disabling timer..."
    systemctl stop gost-monitor.timer 2>/dev/null || true
    systemctl disable gost-monitor.timer 2>/dev/null || true
    systemctl stop gost-monitor.service 2>/dev/null || true

    log "Removing systemd units..."
    rm -f "$TIMER_FILE" "$SVC_FILE"
    systemctl daemon-reload
    systemctl reset-failed gost-monitor.service gost-monitor.timer 2>/dev/null || true

    log "Removing script..."
    rm -f "$SCRIPT_PATH"

    info "Keeping state dir ($STATE_DIR) — contains reboot history / action log."
    info "Remove it manually with: sudo rm -rf $STATE_DIR"
    log "Uninstalled."
}

show_status() {
    echo "=== timer ==="
    systemctl status gost-monitor.timer --no-pager 2>&1 | head -10 || true
    echo ""
    echo "=== gost target ==="
    if gost_is_installed; then
        echo "gost installed — full tiered checks (A/B/C/D) active."
    else
        echo "gost NOT installed — watchdog mode (only tier D outbound check)."
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
gost-monitor — health-check + self-heal for gost SOCKS5

Usage: sudo bash $0 <command>

Commands:
  install         Install script + systemd timer (every ${TIMER_INTERVAL}),
                  then auto-detect whether hairpin check is usable.
  check           Run one health-check pass (used by the timer).
  verify-hairpin  Re-run the hairpin self-test (enable/disable accordingly).
  status          Show timer state, mode, recent actions and reboots.
  uninstall       Remove timer, service and script (keeps state dir).
  help            This message.

Environment overrides:
  MONITOR_NETIF             primary interface  (default: ens5)
  MONITOR_DISABLE_HAIRPIN   set to 1 to force-disable hairpin check

Escalation per check:
  A. service down / not listening    → restart gost
  B. loopback proxy fails            → restart gost  → networkd → reboot
  C. hairpin fails (if enabled)      → restart networkd → reboot
  D. no outbound internet            → restart networkd → reboot

Reboot rate-limit: ${MAX_REBOOTS_PER_DAY}/day, ≥${MIN_REBOOT_INTERVAL_SEC}s apart.

Logs:
  Actions:  $ACTION_LOG
  Reboots:  $REBOOT_LOG
  Journal:  journalctl -u gost-monitor.service
EOF
}

main() {
    case "${1:-help}" in
        install)         install_monitor ;;
        uninstall|remove) uninstall_monitor ;;
        check)           run_check ;;
        verify-hairpin)  verify_hairpin ;;
        status)          show_status ;;
        help|-h|--help)  usage ;;
        *) err "Unknown command: $1"; echo; usage; exit 1 ;;
    esac
}

main "$@"
