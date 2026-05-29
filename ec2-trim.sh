#!/usr/bin/env bash
# ec2-trim — remove default Ubuntu/EC2 services not needed for a small proxy host
#
# Targets (each can be skipped via env var, see help):
#   snapd stack    — incl. amazon-ssm-agent + core22
#                    saves ~30 MB RAM, ~900 MB disk
#   multipath-tools (multipathd)
#                    saves ~27 MB RAM (EC2 with EBS doesn't need this)
#
# Target OS: Ubuntu 20.04+ / Debian 11+
#
# IMPORTANT CONSEQUENCES of removing snapd:
#   - AWS Session Manager / SSM Run Command will stop working
#     (no console-based shell, no SSM-driven scripts)
#   - Restore with: sudo bash ec2-trim.sh restore
#
# Usage:
#   sudo bash ec2-trim.sh purge           # remove (asks for confirmation)
#   sudo YES=1 bash ec2-trim.sh purge     # remove without confirmation
#   sudo bash ec2-trim.sh restore         # reinstall everything
#   sudo bash ec2-trim.sh status          # show current state + memory
#   sudo bash ec2-trim.sh help

set -euo pipefail

KEEP_SNAPD="${KEEP_SNAPD:-0}"
KEEP_MULTIPATH="${KEEP_MULTIPATH:-0}"
YES="${YES:-0}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[x]${NC} $*" >&2; }
info() { echo -e "${BLUE}[i]${NC} $*"; }

require_root() {
    [[ $EUID -eq 0 ]] || { err "Must run as root. Try: sudo bash $0 $*"; exit 1; }
}

detect_os() {
    command -v apt-get >/dev/null 2>&1 || { err "Only Debian/Ubuntu (apt-based) supported."; exit 1; }
}

mem_used_kb() {
    awk '/^MemTotal:/ {t=$2} /^MemAvailable:/ {a=$2} END {print t-a}' /proc/meminfo
}

# ----------------------------------------------------------------------
# State queries
# ----------------------------------------------------------------------

snapd_present() {
    dpkg -l snapd 2>/dev/null | grep -q '^ii'
}

multipath_present() {
    dpkg -l multipath-tools 2>/dev/null | grep -q '^ii'
}

# ----------------------------------------------------------------------
# Purge actions
# ----------------------------------------------------------------------

purge_snapd() {
    if ! snapd_present; then
        info "snapd already removed — skipping."
        return 0
    fi

    log "Removing all installed snaps..."
    if command -v snap >/dev/null 2>&1; then
        # Order matters: app snaps first, then core/base, then snapd itself
        for s in $(snap list 2>/dev/null | awk 'NR>1 && $1!="snapd" && $1!~/^core/ {print $1}'); do
            log "  snap remove --purge $s"
            snap remove --purge "$s" 2>&1 | tail -2 || true
        done
        for s in $(snap list 2>/dev/null | awk 'NR>1 && $1~/^core/ {print $1}'); do
            log "  snap remove --purge $s"
            snap remove --purge "$s" 2>&1 | tail -2 || true
        done
        if snap list 2>/dev/null | awk 'NR>1 {print $1}' | grep -q '^snapd$'; then
            log "  snap remove --purge snapd"
            snap remove --purge snapd 2>&1 | tail -2 || true
        fi
    fi

    log "Stopping snapd services..."
    systemctl stop snapd.service snapd.socket snapd.seeded.service snapd.apparmor.service 2>/dev/null || true

    log "apt-get purge snapd..."
    DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq snapd >/dev/null

    log "Removing residual directories..."
    rm -rf /snap /var/lib/snapd /var/cache/snapd /root/snap 2>/dev/null || true
    # Per-user snap dirs
    for home in /home/*; do
        [[ -d "$home" ]] && rm -rf "$home/snap" 2>/dev/null || true
    done

    # Prevent snapd from being auto-reinstalled
    if [[ ! -f /etc/apt/preferences.d/no-snap.pref ]]; then
        cat > /etc/apt/preferences.d/no-snap.pref <<'EOF'
# Prevent accidental snapd reinstallation
Package: snapd
Pin: release a=*
Pin-Priority: -10
EOF
        info "Added apt pin to block snapd reinstall (/etc/apt/preferences.d/no-snap.pref)"
    fi

    log "snapd stack removed."
}

purge_multipath() {
    if ! multipath_present; then
        info "multipath-tools already removed — skipping."
        return 0
    fi

    log "Disabling multipathd..."
    systemctl disable --now multipathd.service multipathd.socket 2>/dev/null || true

    log "apt-get purge multipath-tools..."
    DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq multipath-tools >/dev/null

    log "multipath-tools removed."
}

# ----------------------------------------------------------------------
# Restore actions
# ----------------------------------------------------------------------

restore_snapd() {
    if snapd_present; then
        info "snapd already installed — skipping."
    else
        # Remove pin first if we set it
        rm -f /etc/apt/preferences.d/no-snap.pref
        log "apt-get install snapd..."
        apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq snapd >/dev/null
        systemctl enable --now snapd.socket snapd.service 2>/dev/null || true
        log "Waiting for snapd to come online..."
        for _ in 1 2 3 4 5 6 7 8 9 10; do
            if snap version >/dev/null 2>&1; then break; fi
            sleep 2
        done
    fi

    if command -v snap >/dev/null 2>&1; then
        if ! snap list 2>/dev/null | awk 'NR>1 {print $1}' | grep -q '^amazon-ssm-agent$'; then
            log "Installing amazon-ssm-agent..."
            snap install amazon-ssm-agent --classic 2>&1 | tail -3 || warn "amazon-ssm-agent install failed"
        else
            info "amazon-ssm-agent already installed."
        fi
    fi
}

restore_multipath() {
    if multipath_present; then
        info "multipath-tools already installed — skipping."
        return 0
    fi
    log "apt-get install multipath-tools..."
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq multipath-tools >/dev/null
    systemctl enable --now multipathd.service 2>/dev/null || true
}

# ----------------------------------------------------------------------
# Subcommands
# ----------------------------------------------------------------------

do_purge() {
    require_root
    detect_os

    echo ""
    echo "About to purge from this server:"
    [[ "$KEEP_SNAPD" != "1" ]] && \
        echo "  - snapd (incl. amazon-ssm-agent, core22) — disables AWS SSM"
    [[ "$KEEP_MULTIPATH" != "1" ]] && \
        echo "  - multipath-tools (multipathd)"
    echo ""

    if [[ "$YES" != "1" ]]; then
        read -r -p "Proceed? [y/N] " ans
        [[ "$ans" =~ ^[Yy]$ ]] || { info "Aborted."; exit 0; }
    fi

    local before after saved
    before=$(mem_used_kb)

    [[ "$KEEP_SNAPD"     != "1" ]] && purge_snapd
    [[ "$KEEP_MULTIPATH" != "1" ]] && purge_multipath

    log "apt-get autoremove..."
    DEBIAN_FRONTEND=noninteractive apt-get autoremove -y -qq >/dev/null

    after=$(mem_used_kb)
    saved=$(( before - after ))
    echo ""
    log "Done. Memory used: $((before/1024)) MiB → $((after/1024)) MiB (saved ~$((saved/1024)) MiB)"
    info "Disk: run 'df -h /' to see freed space (snap dirs were ~900 MB)"
}

do_restore() {
    require_root
    detect_os

    if [[ "$YES" != "1" ]]; then
        echo "About to reinstall on this server:"
        [[ "$KEEP_SNAPD"     != "1" ]] && echo "  - snapd + amazon-ssm-agent"
        [[ "$KEEP_MULTIPATH" != "1" ]] && echo "  - multipath-tools"
        read -r -p "Proceed? [y/N] " ans
        [[ "$ans" =~ ^[Yy]$ ]] || { info "Aborted."; exit 0; }
    fi

    [[ "$KEEP_SNAPD"     != "1" ]] && restore_snapd
    [[ "$KEEP_MULTIPATH" != "1" ]] && restore_multipath

    log "Restore complete."
}

do_status() {
    echo "=== memory ==="
    free -h | awk '/^Mem:/ {print "  Total: " $2 "  Used: " $3 "  Available: " $7}'
    echo ""
    echo "=== package state ==="
    printf "  snapd            : %s\n" "$(snapd_present && echo installed || echo absent)"
    printf "  multipath-tools  : %s\n" "$(multipath_present && echo installed || echo absent)"
    echo ""
    if snapd_present && command -v snap >/dev/null 2>&1; then
        echo "=== installed snaps ==="
        snap list 2>/dev/null || true
        echo ""
        echo "=== snap disk usage ==="
        du -sh /snap /var/lib/snapd 2>/dev/null | sed 's/^/  /'
        echo ""
    fi
    echo "=== top 5 memory processes ==="
    ps -eo pid,pmem,rss,comm --sort=-rss --no-headers \
        | head -5 \
        | awk '{printf "  PID %s  MEM %s%%  RSS %s KB  %s\n",$1,$2,$3,$4}'
}

usage() {
    cat <<EOF
ec2-trim — remove unneeded snapd + multipath-tools from a small EC2 host

Usage: sudo bash $0 <command>

Commands:
  purge       Remove snapd (incl. amazon-ssm-agent) and multipath-tools.
              Adds an apt pin to block snapd auto-reinstall.
  restore     Reinstall what was removed (snapd + amazon-ssm-agent,
              multipath-tools).
  status      Show current memory + package state.
  help        This message.

Environment overrides:
  KEEP_SNAPD=1       skip snapd actions (only touch multipath)
  KEEP_MULTIPATH=1   skip multipath actions (only touch snapd)
  YES=1              skip confirmation prompt

Caveats:
  - Removing snapd disables AWS Session Manager / SSM Run Command.
    Use 'restore' to bring them back.
  - multipath-tools is unused on standard EC2 with EBS volumes.

Examples:
  sudo bash $0 purge
  sudo YES=1 KEEP_MULTIPATH=1 bash $0 purge    # only remove snapd
  sudo bash $0 restore
  sudo bash $0 status
EOF
}

main() {
    case "${1:-help}" in
        purge)          do_purge ;;
        restore)        do_restore ;;
        status)         do_status ;;
        help|-h|--help) usage ;;
        *) err "Unknown command: $1"; echo; usage; exit 1 ;;
    esac
}

main "$@"
