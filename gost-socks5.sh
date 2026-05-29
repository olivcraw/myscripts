#!/usr/bin/env bash
# gost trojan + SOCKS5 — installs TWO endpoints in one gost process:
#   - plain SOCKS5  on PLAIN_PORT   (default 8443, no encryption)
#   - trojan        on TROJAN_PORT  (default 8444, TLS, self-signed cert)
#
# Both endpoints share the same password (auto-generated). SOCKS5 also
# uses a username; trojan authenticates by password only (protocol spec).
# Target OS: Ubuntu 20.04+ / Debian 11+
#
# NOTE: The plain SOCKS5 endpoint sends credentials AND payload in cleartext.
# Use a strong password and ideally an IP allow-list.
#
# Usage:
#   sudo bash gost-socks5.sh install
#   sudo bash gost-socks5.sh uninstall
#   sudo bash gost-socks5.sh status

set -euo pipefail

# ---------- Configuration ----------
GOST_VERSION_FALLBACK="3.0.0"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/gost"
SERVICE_FILE="/etc/systemd/system/gost.service"
PLAIN_PORT="${GOST_PLAIN_PORT:-8443}"
TROJAN_PORT="${GOST_TROJAN_PORT:-8444}"
DEFAULT_USER="${GOST_USER:-proxyuser}"
# -----------------------------------

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[x]${NC} $*" >&2; }
info() { echo -e "${BLUE}[i]${NC} $*"; }

require_root() {
    if [[ $EUID -ne 0 ]]; then
        err "Must run as root. Try: sudo bash $0 $*"
        exit 1
    fi
}

detect_arch() {
    case "$(uname -m)" in
        x86_64)  echo "amd64" ;;
        aarch64) echo "arm64" ;;
        armv7l)  echo "armv7" ;;
        *)       err "Unsupported architecture: $(uname -m)"; exit 1 ;;
    esac
}

detect_os() {
    if ! command -v apt-get >/dev/null 2>&1; then
        err "This script only supports Debian/Ubuntu (apt-based) systems."
        exit 1
    fi
}

server_ip() {
    curl -fsSL --max-time 5 https://api.ipify.org 2>/dev/null \
        || curl -fsSL --max-time 5 https://ifconfig.me 2>/dev/null \
        || ip -4 addr show scope global 2>/dev/null | awk '/inet/ {print $2}' | cut -d/ -f1 | head -n1 \
        || echo "your-server-ip"
}

latest_gost_version() {
    local v
    v=$(curl -fsSL --max-time 5 https://api.github.com/repos/go-gost/gost/releases/latest 2>/dev/null \
        | grep -m1 '"tag_name":' \
        | sed -E 's/.*"v?([^"]+)".*/\1/' || true)
    if [[ -n "${v:-}" ]]; then
        echo "$v"
    else
        echo "$GOST_VERSION_FALLBACK"
    fi
}

random_password() {
    openssl rand -base64 32 | tr -d '/+=\n' | head -c 32
}

# ----------------------------------------------------------------------
install_gost() {
    require_root
    detect_os

    if [[ -f "$SERVICE_FILE" ]] || command -v gost >/dev/null 2>&1; then
        warn "gost looks like it's already installed."
        read -r -p "Reinstall? Existing config will be backed up. [y/N] " ans
        [[ "$ans" =~ ^[Yy]$ ]] || { info "Aborted."; exit 0; }
        if [[ -d "$CONFIG_DIR" ]]; then
            local bak="${CONFIG_DIR}.bak.$(date +%s)"
            mv "$CONFIG_DIR" "$bak"
            warn "Old config backed up to $bak"
        fi
        systemctl stop gost 2>/dev/null || true
    fi

    local arch version
    arch=$(detect_arch)
    log "Architecture: $arch"

    log "Installing dependencies (curl, tar, openssl, ufw, fail2ban)..."
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        curl tar openssl ufw ca-certificates fail2ban >/dev/null
    systemctl enable --now fail2ban >/dev/null 2>&1 || true

    version=$(latest_gost_version)
    log "Downloading gost v${version}..."
    local tmp url
    tmp=$(mktemp -d)
    url="https://github.com/go-gost/gost/releases/download/v${version}/gost_${version}_linux_${arch}.tar.gz"
    if ! curl -fsSL -o "$tmp/gost.tar.gz" "$url"; then
        err "Download failed: $url"
        err "Check the release page: https://github.com/go-gost/gost/releases"
        rm -rf "$tmp"
        exit 1
    fi
    tar -xzf "$tmp/gost.tar.gz" -C "$tmp"
    install -m 755 "$tmp/gost" "$INSTALL_DIR/gost"
    rm -rf "$tmp"
    log "Installed: $($INSTALL_DIR/gost -V 2>&1 | head -n1)"

    mkdir -p "$CONFIG_DIR"
    chmod 700 "$CONFIG_DIR"

    local username password ip
    username="$DEFAULT_USER"
    password=$(random_password)
    ip=$(server_ip)

    log "Generating self-signed TLS cert (10y) for trojan..."
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
        -keyout "$CONFIG_DIR/server.key" \
        -out   "$CONFIG_DIR/server.crt" \
        -subj  "/CN=${ip}" >/dev/null 2>&1
    chmod 600 "$CONFIG_DIR/server.key"
    chmod 644 "$CONFIG_DIR/server.crt"

    cat > "$CONFIG_DIR/credentials" <<EOF
USERNAME=$username
PASSWORD=$password
PLAIN_PORT=$PLAIN_PORT
TROJAN_PORT=$TROJAN_PORT
# Backward compat for gost-monitor (uses PORT)
PORT=$PLAIN_PORT
EOF
    chmod 600 "$CONFIG_DIR/credentials"

    cat > "$CONFIG_DIR/gost.yaml" <<EOF
services:
- name: socks5-plain
  addr: ":${PLAIN_PORT}"
  handler:
    type: socks5
    auth:
      username: ${username}
      password: ${password}
  listener:
    type: tcp

- name: trojan
  addr: ":${TROJAN_PORT}"
  handler:
    type: trojan
    auth:
      username: ${username}
      password: ${password}
  listener:
    type: tls
    tls:
      certFile: ${CONFIG_DIR}/server.crt
      keyFile: ${CONFIG_DIR}/server.key
EOF
    chmod 600 "$CONFIG_DIR/gost.yaml"
    log "Config written: $CONFIG_DIR/gost.yaml"

    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=GOST trojan + plain SOCKS5
After=network.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/gost -C ${CONFIG_DIR}/gost.yaml
Restart=on-failure
RestartSec=5
LimitNOFILE=65535
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now gost

    if command -v ufw >/dev/null 2>&1; then
        ufw allow "${PLAIN_PORT}/tcp"  >/dev/null 2>&1 || true
        ufw allow "${TROJAN_PORT}/tcp" >/dev/null 2>&1 || true
        log "Opened firewall ports ${PLAIN_PORT}/tcp and ${TROJAN_PORT}/tcp (ufw)"
    fi

    sleep 1
    if ! systemctl is-active --quiet gost; then
        err "gost failed to start. Diagnose with: journalctl -u gost -n 50"
        exit 1
    fi

    print_connection_info
}

print_connection_info() {
    local ip user pass pport tport fp
    ip=$(server_ip)
    if [[ -f "$CONFIG_DIR/credentials" ]]; then
        # shellcheck disable=SC1091
        source "$CONFIG_DIR/credentials"
        user="$USERNAME"; pass="$PASSWORD"
        pport="${PLAIN_PORT:-$PORT}"; tport="${TROJAN_PORT:-}"
    else
        user="?"; pass="?"; pport="$PLAIN_PORT"; tport="$TROJAN_PORT"
    fi
    if [[ -f "$CONFIG_DIR/server.crt" ]]; then
        fp=$(openssl x509 -in "$CONFIG_DIR/server.crt" -noout -fingerprint -sha256 2>/dev/null | sed 's/^.*=//')
    fi

    echo
    echo "============================================================"
    log "gost trojan + plain SOCKS5 is running"
    echo "============================================================"
    info "Server       : ${ip}"
    info "Username     : ${user}             (SOCKS5 only)"
    info "Password     : ${pass}             (shared)"
    info "Plain SOCKS5 : ${ip}:${pport}"
    info "Trojan (TLS) : ${ip}:${tport}  (self-signed cert)"
    [[ -n "${fp:-}" ]] && info "Cert SHA-256 : ${fp}"
    echo
    echo "------------------------------------------------------------"
    echo " 1) Trojan over TLS  (standard trojan URL)"
    echo "------------------------------------------------------------"
    echo "    trojan://${pass}@${ip}:${tport}?security=tls&allowInsecure=1&type=tcp&sni=${ip}#gost-trojan"
    echo
    echo "    Notes:"
    echo "      - allowInsecure=1 is required (self-signed cert)"
    echo "      - Works with: Shadowrocket, Clash Meta, V2RayN, sing-box, etc."
    echo
    echo "------------------------------------------------------------"
    echo " 2) Plain SOCKS5  (no encryption)"
    echo "------------------------------------------------------------"
    echo "    socks5://${user}:${pass}@${ip}:${pport}"
    echo
    warn "Plain SOCKS5 carries credentials + traffic IN THE CLEAR."
    warn "Trojan endpoint is TLS-encrypted but uses a self-signed cert,"
    warn "so the client must allow it (allowInsecure=1 / pin SHA-256)."
    echo
    info "Open in AWS Security Group: TCP ${pport} AND TCP ${tport}"
    info "Credentials saved at:       ${CONFIG_DIR}/credentials"
    echo "============================================================"
}

# ----------------------------------------------------------------------
status_gost() {
    if [[ ! -x "$INSTALL_DIR/gost" && ! -f "$SERVICE_FILE" ]]; then
        warn "gost is not installed."
        exit 0
    fi
    systemctl status gost --no-pager 2>/dev/null || true
    echo
    if [[ -f "$CONFIG_DIR/credentials" ]]; then
        print_connection_info
    fi
}

# ----------------------------------------------------------------------
uninstall_gost() {
    require_root
    local pport tport
    if [[ -f "$CONFIG_DIR/credentials" ]]; then
        # shellcheck disable=SC1091
        source "$CONFIG_DIR/credentials"
        pport="${PLAIN_PORT:-${PORT:-$PLAIN_PORT}}"
        tport="${TROJAN_PORT:-${TLS_PORT:-$TROJAN_PORT}}"
    else
        pport="$PLAIN_PORT"
        tport="$TROJAN_PORT"
    fi

    warn "This will COMPLETELY remove:"
    echo "  - service:     $SERVICE_FILE"
    echo "  - binary:      $INSTALL_DIR/gost"
    echo "  - config dir:  $CONFIG_DIR (credentials, yaml, cert, key)"
    echo "  - firewall:    ufw rules for ${pport}/tcp and ${tport}/tcp"
    read -r -p "Proceed? [y/N] " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        info "Aborted."
        exit 0
    fi

    log "Stopping & disabling service..."
    systemctl stop gost 2>/dev/null || true
    systemctl disable gost 2>/dev/null || true

    log "Removing systemd unit..."
    rm -f "$SERVICE_FILE"
    systemctl daemon-reload
    systemctl reset-failed gost 2>/dev/null || true

    log "Removing binary..."
    rm -f "$INSTALL_DIR/gost"

    log "Removing config..."
    rm -rf "$CONFIG_DIR"
    rm -rf "${CONFIG_DIR}".bak.* 2>/dev/null || true

    log "Removing firewall rules..."
    if command -v ufw >/dev/null 2>&1; then
        ufw delete allow "${pport}/tcp" >/dev/null 2>&1 || true
        ufw delete allow "${tport}/tcp" >/dev/null 2>&1 || true
    fi

    log "Uninstall complete. Verifying..."
    local leftover=0
    for f in "$SERVICE_FILE" "$INSTALL_DIR/gost" "$CONFIG_DIR"; do
        if [[ -e "$f" ]]; then
            err "Leftover: $f"
            leftover=1
        fi
    done
    if systemctl list-unit-files 2>/dev/null | grep -q '^gost\.service'; then
        err "Leftover: gost.service still registered"
        leftover=1
    fi
    if [[ $leftover -eq 0 ]]; then
        log "All gost artifacts removed cleanly."
        info "Note: fail2ban was kept (it's a general-purpose tool)."
        info "Remove it manually if you don't need it: sudo apt-get purge fail2ban"
    else
        warn "Some artifacts remain — see above."
        exit 1
    fi
}

# ----------------------------------------------------------------------
usage() {
    cat <<EOF
gost trojan + plain SOCKS5 — install / uninstall helper

Usage: sudo bash $0 <command>

Commands:
  install     Download gost, generate random password and self-signed cert,
              create systemd service exposing TWO endpoints:
                * plain SOCKS5 (PLAIN_PORT)
                * trojan over TLS (TROJAN_PORT)
              Open firewall, install fail2ban, start service.
  uninstall   Stop service and remove ALL artifacts (binary, config,
              cert, systemd unit, firewall rules)
  status      Show service status and saved credentials
  help        This message

Environment overrides:
  GOST_PLAIN_PORT    plain SOCKS5 port    (default: 8443)
  GOST_TROJAN_PORT   trojan over TLS port (default: 8444)
  GOST_USER          SOCKS5 username      (default: proxyuser)

Examples:
  sudo bash $0 install
  sudo GOST_PLAIN_PORT=10443 GOST_TROJAN_PORT=10444 bash $0 install
  sudo bash $0 status
  sudo bash $0 uninstall
EOF
}

main() {
    case "${1:-help}" in
        install)        install_gost ;;
        uninstall|remove|purge) uninstall_gost ;;
        status)         status_gost ;;
        help|-h|--help) usage ;;
        *) err "Unknown command: $1"; echo; usage; exit 1 ;;
    esac
}

main "$@"
