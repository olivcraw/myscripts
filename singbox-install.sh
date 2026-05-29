#!/usr/bin/env bash
# sing-box install — single process serving two inbounds:
#   - plain SOCKS5     on SOCKS_PORT  (default 8443)
#   - trojan over TLS  on TROJAN_PORT (default 443, self-signed cert)
#     443 is the standard HTTPS port; using it strengthens the disguise
#     since real HTTPS sites all live here too.
#
# Plus an nginx-based trojan FALLBACK on 127.0.0.1:80 that reverse-proxies
# to a real public site (default www.google.com). Probes that hit the
# trojan port without a valid trojan password see real website content,
# so the port doesn't look like a proxy.
#
# Both inbounds share one password (auto-generated). SOCKS5 also uses a
# username; trojan only uses the password (per protocol).
# Target OS: Ubuntu 20.04+ / Debian 11+
#
# Usage:
#   sudo bash singbox-install.sh install
#   sudo bash singbox-install.sh uninstall
#   sudo bash singbox-install.sh status

set -euo pipefail

# ---------- Configuration ----------
SINGBOX_VERSION_FALLBACK="1.10.0"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/sing-box"
SERVICE_FILE="/etc/systemd/system/sing-box.service"
NGINX_SITE_CONF="/etc/nginx/sites-available/singbox-fallback.conf"
NGINX_SITE_LINK="/etc/nginx/sites-enabled/singbox-fallback.conf"
SOCKS_PORT="${SINGBOX_SOCKS_PORT:-8443}"
TROJAN_PORT="${SINGBOX_TROJAN_PORT:-443}"
FALLBACK_TARGET="${SINGBOX_FALLBACK_TARGET:-www.google.com}"
DEFAULT_USER="${SINGBOX_USER:-proxyuser}"
# direct-outbound domain resolution strategy. Default ipv4_only so servers
# without working IPv6 (e.g. EC2 with no IPv6) don't return SOCKS5 "network
# unreachable" (0x03) when a target resolves to an AAAA record.
# Override with prefer_ipv6 / prefer_ipv4 / ipv6_only if the host has IPv6.
OUTBOUND_STRATEGY="${SINGBOX_OUTBOUND_STRATEGY:-ipv4_only}"
# -----------------------------------

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[x]${NC} $*" >&2; }
info() { echo -e "${BLUE}[i]${NC} $*"; }

require_root() {
    [[ $EUID -eq 0 ]] || { err "Must run as root. Try: sudo bash $0 $*"; exit 1; }
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
    command -v apt-get >/dev/null 2>&1 || { err "Only Debian/Ubuntu (apt-based) supported."; exit 1; }
}

server_ip() {
    curl -fsSL --max-time 5 https://api.ipify.org 2>/dev/null \
        || curl -fsSL --max-time 5 https://ifconfig.me 2>/dev/null \
        || ip -4 addr show scope global 2>/dev/null | awk '/inet/ {print $2}' | cut -d/ -f1 | head -n1 \
        || echo "your-server-ip"
}

latest_singbox_version() {
    # Use bash regex on the buffered response — avoids SIGPIPE under pipefail
    # which would otherwise trip when grep -m1 closes its stdin early.
    local resp v=""
    resp=$(curl -fsSL --max-time 5 \
        https://api.github.com/repos/SagerNet/sing-box/releases/latest 2>/dev/null || true)
    if [[ -n "$resp" ]] && [[ "$resp" =~ \"tag_name\":[[:space:]]*\"v?([^\"]+)\" ]]; then
        v="${BASH_REMATCH[1]}"
    fi
    if [[ -n "$v" ]]; then
        echo "$v"
    else
        echo "$SINGBOX_VERSION_FALLBACK"
    fi
}

random_password() {
    openssl rand -base64 32 | tr -d '/+=\n' | head -c 32
}

# ----------------------------------------------------------------------
install_singbox() {
    require_root
    detect_os

    # install_mode is one of: fresh | overlay | rotate
    #   fresh   — no existing install, generate everything
    #   overlay — existing install detected; KEEP credentials and TLS cert,
    #             only refresh binary/config/nginx/firewall
    #   rotate  — existing install detected; generate NEW credentials (and
    #             new cert), back up old config dir
    local install_mode="fresh"
    local existing_username="" existing_password=""

    if [[ -f "$SERVICE_FILE" ]] || command -v sing-box >/dev/null 2>&1; then
        local mode_env="${SINGBOX_REINSTALL_MODE:-}"
        if [[ -n "$mode_env" ]]; then
            case "${mode_env,,}" in
                overlay|keep)  install_mode="overlay" ;;
                rotate|reset)  install_mode="rotate" ;;
                abort|no)      info "Aborted via SINGBOX_REINSTALL_MODE=$mode_env"; exit 0 ;;
                *)             err "Invalid SINGBOX_REINSTALL_MODE: $mode_env (use overlay|rotate|abort)"; exit 1 ;;
            esac
            log "Existing install detected — mode: $install_mode (from SINGBOX_REINSTALL_MODE)"
        else
            warn "sing-box looks like it's already installed."
            echo "  [O]verlay  keep username/password + TLS cert; refresh binary/config/nginx (default)"
            echo "  [R]otate   generate NEW random password and cert (all clients must reconfigure)"
            echo "  [N]o       abort"
            read -r -p "Choice [O/r/N]: " ans
            case "${ans,,}" in
                ""|o|y|overlay)  install_mode="overlay" ;;
                r|rotate)        install_mode="rotate" ;;
                *)               info "Aborted."; exit 0 ;;
            esac
            log "Install mode: $install_mode"
        fi

        # Capture existing credentials BEFORE any rewrite, for overlay mode.
        if [[ "$install_mode" == "overlay" ]]; then
            if [[ -r "$CONFIG_DIR/credentials" ]]; then
                existing_username=$(grep -m1 '^USERNAME=' "$CONFIG_DIR/credentials" | cut -d= -f2- || true)
                existing_password=$(grep -m1 '^PASSWORD=' "$CONFIG_DIR/credentials" | cut -d= -f2- || true)
                if [[ -z "$existing_password" ]]; then
                    warn "Overlay requested but no PASSWORD in credentials file — falling back to rotate."
                    install_mode="rotate"
                else
                    log "Captured existing credentials (username: ${existing_username})"
                fi
            else
                warn "Overlay requested but no $CONFIG_DIR/credentials — falling back to rotate."
                install_mode="rotate"
            fi
        fi

        # Backup old config dir only when rotating/fresh; overlay keeps it in place.
        if [[ "$install_mode" != "overlay" && -d "$CONFIG_DIR" ]]; then
            local bak="${CONFIG_DIR}.bak.$(date +%s)"
            mv "$CONFIG_DIR" "$bak"
            warn "Old config backed up to $bak"
        fi
        systemctl stop sing-box 2>/dev/null || true
    fi

    local arch version
    arch=$(detect_arch)
    log "Architecture: $arch"

    log "Installing dependencies (curl, tar, openssl, ufw, fail2ban, nginx)..."
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        curl tar openssl ufw ca-certificates fail2ban nginx >/dev/null
    systemctl enable --now fail2ban >/dev/null 2>&1 || true

    version=$(latest_singbox_version)
    log "Downloading sing-box v${version}..."
    local tmp url subdir
    tmp=$(mktemp -d)
    url="https://github.com/SagerNet/sing-box/releases/download/v${version}/sing-box-${version}-linux-${arch}.tar.gz"
    if ! curl -fsSL -o "$tmp/sb.tar.gz" "$url"; then
        err "Download failed: $url"
        err "Check the release page: https://github.com/SagerNet/sing-box/releases"
        rm -rf "$tmp"
        exit 1
    fi
    tar -xzf "$tmp/sb.tar.gz" -C "$tmp"
    subdir="sing-box-${version}-linux-${arch}"
    if [[ ! -x "$tmp/$subdir/sing-box" ]]; then
        err "Binary not found at $tmp/$subdir/sing-box"
        rm -rf "$tmp"
        exit 1
    fi
    install -m 755 "$tmp/$subdir/sing-box" "$INSTALL_DIR/sing-box"
    rm -rf "$tmp"
    log "Installed: $($INSTALL_DIR/sing-box version 2>&1 | head -n1)"

    mkdir -p "$CONFIG_DIR"
    chmod 700 "$CONFIG_DIR"

    local username password ip
    ip=$(server_ip)
    if [[ "$install_mode" == "overlay" && -n "$existing_password" ]]; then
        username="${existing_username:-$DEFAULT_USER}"
        password="$existing_password"
        log "Preserving existing credentials (overlay mode — clients keep working)"
    else
        username="$DEFAULT_USER"
        password=$(random_password)
        log "Generated new random credentials"
    fi

    if [[ "$install_mode" == "overlay" \
          && -f "$CONFIG_DIR/server.crt" && -f "$CONFIG_DIR/server.key" ]]; then
        log "Preserving existing TLS cert"
    else
        log "Generating self-signed TLS cert (10y) for trojan..."
        openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
            -keyout "$CONFIG_DIR/server.key" \
            -out   "$CONFIG_DIR/server.crt" \
            -subj  "/CN=${ip}" >/dev/null 2>&1
        chmod 600 "$CONFIG_DIR/server.key"
        chmod 644 "$CONFIG_DIR/server.crt"
    fi

    cat > "$CONFIG_DIR/credentials" <<EOF
USERNAME=$username
PASSWORD=$password
SOCKS_PORT=$SOCKS_PORT
TROJAN_PORT=$TROJAN_PORT
# Backward-compat for any monitor reading PORT:
PORT=$SOCKS_PORT
EOF
    chmod 600 "$CONFIG_DIR/credentials"

    cat > "$CONFIG_DIR/config.json" <<EOF
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "inbounds": [
    {
      "type": "socks",
      "tag": "socks-in",
      "listen": "::",
      "listen_port": ${SOCKS_PORT},
      "users": [
        { "username": "${username}", "password": "${password}" }
      ]
    },
    {
      "type": "trojan",
      "tag": "trojan-in",
      "listen": "::",
      "listen_port": ${TROJAN_PORT},
      "users": [
        { "name": "${username}", "password": "${password}" }
      ],
      "tls": {
        "enabled": true,
        "certificate_path": "${CONFIG_DIR}/server.crt",
        "key_path": "${CONFIG_DIR}/server.key"
      },
      "fallback": {
        "server": "127.0.0.1",
        "server_port": 80
      }
    }
  ],
  "outbounds": [
    { "type": "direct", "tag": "direct", "domain_strategy": "${OUTBOUND_STRATEGY}" }
  ]
}
EOF
    chmod 600 "$CONFIG_DIR/config.json"
    log "Config written: $CONFIG_DIR/config.json"

    log "Validating config..."
    if ! "$INSTALL_DIR/sing-box" check -c "$CONFIG_DIR/config.json" 2>&1; then
        err "Config validation failed. Aborting before starting service."
        exit 1
    fi

    log "Configuring nginx reverse proxy to https://${FALLBACK_TARGET} ..."
    # Remove default site so port-80 binding belongs to us
    rm -f /etc/nginx/sites-enabled/default

    cat > "$NGINX_SITE_CONF" <<EOF
# Trojan fallback — receives plaintext HTTP from sing-box when a probe
# hits the trojan port without a valid trojan handshake. Reverse-proxies
# to a real public site so the port doesn't look like a proxy.
server {
    listen 127.0.0.1:80 default_server;
    server_name _;
    server_tokens off;

    resolver 1.1.1.1 8.8.8.8 valid=300s ipv6=off;
    resolver_timeout 5s;

    location / {
        proxy_pass         https://${FALLBACK_TARGET};
        proxy_http_version 1.1;
        proxy_ssl_server_name on;
        proxy_ssl_name        ${FALLBACK_TARGET};
        proxy_set_header      Host               ${FALLBACK_TARGET};
        proxy_set_header      Accept-Encoding    "";
        proxy_set_header      X-Real-IP          "";
        proxy_set_header      X-Forwarded-For    "";
        proxy_set_header      X-Forwarded-Proto  https;
        proxy_set_header      Connection         "";
        proxy_redirect        off;
        proxy_connect_timeout 5s;
        proxy_read_timeout    30s;
    }
}
EOF
    ln -sf "$NGINX_SITE_CONF" "$NGINX_SITE_LINK"

    if ! nginx -t 2>&1; then
        err "nginx config test failed. Aborting."
        exit 1
    fi
    systemctl enable nginx >/dev/null 2>&1 || true
    # Use restart (not reload): if a previous nginx is bound to 0.0.0.0:80
    # via the default site, a graceful reload can't bind 127.0.0.1:80 since
    # the port is already covered. restart drops the old listeners cleanly.
    systemctl restart nginx
    log "nginx fallback active on 127.0.0.1:80 → https://${FALLBACK_TARGET}"

    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=sing-box (trojan + SOCKS5)
After=network.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/sing-box run -c ${CONFIG_DIR}/config.json
Restart=on-failure
RestartSec=5
LimitNOFILE=65535
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=${CONFIG_DIR}

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now sing-box

    if command -v ufw >/dev/null 2>&1; then
        ufw allow "${SOCKS_PORT}/tcp"  >/dev/null 2>&1 || true
        ufw allow "${TROJAN_PORT}/tcp" >/dev/null 2>&1 || true
        log "Opened firewall ports ${SOCKS_PORT}/tcp and ${TROJAN_PORT}/tcp (ufw)"
    fi

    sleep 1
    if ! systemctl is-active --quiet sing-box; then
        err "sing-box failed to start. Diagnose with: journalctl -u sing-box -n 50"
        exit 1
    fi

    print_connection_info
}

print_connection_info() {
    local ip user pass sport tport fp
    ip=$(server_ip)
    if [[ -f "$CONFIG_DIR/credentials" ]]; then
        # shellcheck disable=SC1091
        source "$CONFIG_DIR/credentials"
        user="$USERNAME"; pass="$PASSWORD"
        sport="${SOCKS_PORT:-$PORT}"; tport="${TROJAN_PORT:-}"
    else
        user="?"; pass="?"; sport="$SOCKS_PORT"; tport="$TROJAN_PORT"
    fi
    if [[ -f "$CONFIG_DIR/server.crt" ]]; then
        fp=$(openssl x509 -in "$CONFIG_DIR/server.crt" -noout -fingerprint -sha256 2>/dev/null | sed 's/^.*=//')
    fi

    echo
    echo "============================================================"
    log "sing-box is running (trojan + plain SOCKS5)"
    echo "============================================================"
    info "Server       : ${ip}"
    info "Username     : ${user}             (SOCKS5 only)"
    info "Password     : ${pass}             (shared)"
    info "Plain SOCKS5 : ${ip}:${sport}"
    info "Trojan (TLS) : ${ip}:${tport}  (self-signed cert)"
    [[ -n "${fp:-}" ]] && info "Cert SHA-256 : ${fp}"
    echo
    echo "------------------------------------------------------------"
    echo " 1) Trojan over TLS  (standard trojan URL)"
    echo "------------------------------------------------------------"
    echo "    trojan://${pass}@${ip}:${tport}?security=tls&allowInsecure=1&type=tcp&sni=${ip}#singbox-trojan"
    echo
    echo "    Notes:"
    echo "      - allowInsecure=1 is required (self-signed cert)"
    echo "      - Works with: Shadowrocket, Clash Meta, V2RayN, sing-box client, etc."
    echo
    echo "------------------------------------------------------------"
    echo " 2) Plain SOCKS5  (no encryption)"
    echo "------------------------------------------------------------"
    echo "    socks5://${user}:${pass}@${ip}:${sport}"
    echo
    warn "Plain SOCKS5 carries credentials + traffic IN THE CLEAR."
    warn "Trojan endpoint is TLS-encrypted but uses a self-signed cert,"
    warn "so the client must allow it (allowInsecure=1 / pin SHA-256)."
    echo
    info "Trojan disguise: probes that don't speak trojan get reverse-proxied"
    info "                 by nginx to https://${FALLBACK_TARGET:-www.google.com}"
    info "                 (visible if the visitor accepts the self-signed cert)"
    echo
    info "Open in AWS Security Group: TCP ${sport} AND TCP ${tport}"
    info "Credentials saved at:       ${CONFIG_DIR}/credentials"
    echo "============================================================"
}

# ----------------------------------------------------------------------
status_singbox() {
    if [[ ! -x "$INSTALL_DIR/sing-box" && ! -f "$SERVICE_FILE" ]]; then
        warn "sing-box is not installed."
        exit 0
    fi
    systemctl status sing-box --no-pager 2>/dev/null || true
    echo
    if [[ -f "$CONFIG_DIR/credentials" ]]; then
        print_connection_info
    fi
}

# ----------------------------------------------------------------------
uninstall_singbox() {
    require_root
    local sport tport
    if [[ -f "$CONFIG_DIR/credentials" ]]; then
        # shellcheck disable=SC1091
        source "$CONFIG_DIR/credentials"
        sport="${SOCKS_PORT:-${PORT:-$SOCKS_PORT}}"
        tport="${TROJAN_PORT:-$TROJAN_PORT}"
    else
        sport="$SOCKS_PORT"
        tport="$TROJAN_PORT"
    fi

    warn "This will COMPLETELY remove:"
    echo "  - service:     $SERVICE_FILE"
    echo "  - binary:      $INSTALL_DIR/sing-box"
    echo "  - config dir:  $CONFIG_DIR (credentials, config.json, cert, key)"
    echo "  - nginx site:  $NGINX_SITE_CONF (+ symlink)"
    echo "  - firewall:    ufw rules for ${sport}/tcp and ${tport}/tcp"
    read -r -p "Proceed? [y/N] " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        info "Aborted."
        exit 0
    fi

    log "Stopping & disabling service..."
    systemctl stop sing-box 2>/dev/null || true
    systemctl disable sing-box 2>/dev/null || true

    log "Removing systemd unit..."
    rm -f "$SERVICE_FILE"
    systemctl daemon-reload
    systemctl reset-failed sing-box 2>/dev/null || true

    log "Removing binary..."
    rm -f "$INSTALL_DIR/sing-box"

    log "Removing config..."
    rm -rf "$CONFIG_DIR"
    rm -rf "${CONFIG_DIR}".bak.* 2>/dev/null || true

    log "Removing nginx fallback site..."
    rm -f "$NGINX_SITE_LINK" "$NGINX_SITE_CONF"
    # Restore default nginx site if user wants — we don't force it
    if command -v nginx >/dev/null 2>&1 && systemctl is-active --quiet nginx; then
        nginx -t >/dev/null 2>&1 && systemctl reload nginx || true
    fi

    log "Removing firewall rules..."
    if command -v ufw >/dev/null 2>&1; then
        ufw delete allow "${sport}/tcp" >/dev/null 2>&1 || true
        ufw delete allow "${tport}/tcp" >/dev/null 2>&1 || true
    fi

    log "Uninstall complete. Verifying..."
    local leftover=0
    for f in "$SERVICE_FILE" "$INSTALL_DIR/sing-box" "$CONFIG_DIR" "$NGINX_SITE_LINK" "$NGINX_SITE_CONF"; do
        if [[ -e "$f" ]]; then
            err "Leftover: $f"
            leftover=1
        fi
    done
    if systemctl list-unit-files 2>/dev/null | grep -q '^sing-box\.service'; then
        err "Leftover: sing-box.service still registered"
        leftover=1
    fi
    if [[ $leftover -eq 0 ]]; then
        log "All sing-box artifacts removed cleanly."
        info "Note: nginx and fail2ban were kept (general-purpose tools)."
        info "If you don't need them: sudo apt-get purge nginx fail2ban"
    else
        warn "Some artifacts remain — see above."
        exit 1
    fi
}

usage() {
    cat <<EOF
sing-box install — trojan over TLS + plain SOCKS5 (single process)

Usage: sudo bash $0 <command>

Commands:
  install     Download sing-box, generate random password and self-signed
              cert, create systemd service exposing TWO inbounds:
                * plain SOCKS5 (SOCKS_PORT)
                * trojan over TLS (TROJAN_PORT)
              Open firewall, install fail2ban, start service.
  uninstall   Stop service and remove ALL artifacts (binary, config,
              cert, systemd unit, firewall rules).
  status      Show service status and saved credentials.
  help        This message.

Environment overrides:
  SINGBOX_SOCKS_PORT      plain SOCKS5 port            (default: 8443)
  SINGBOX_TROJAN_PORT     trojan over TLS port         (default: 443)
  SINGBOX_FALLBACK_TARGET nginx reverse-proxy target   (default: www.google.com)
  SINGBOX_USER            SOCKS5 username              (default: proxyuser)
  SINGBOX_OUTBOUND_STRATEGY direct-outbound DNS strategy (default: ipv4_only)
                            ipv4_only avoids SOCKS5 "network unreachable" on
                            hosts without IPv6; use prefer_ipv6 if IPv6 works
  SINGBOX_REINSTALL_MODE  what to do if already installed (no prompt):
                            overlay  keep username/password + cert (recommended)
                            rotate   generate NEW credentials + cert
                            abort    exit without changes

Examples:
  sudo bash $0 install
  sudo SINGBOX_REINSTALL_MODE=overlay bash $0 install   # non-interactive re-install
  sudo SINGBOX_REINSTALL_MODE=rotate  bash $0 install   # cycle the password
  sudo SINGBOX_FALLBACK_TARGET=www.bing.com bash $0 install
  sudo SINGBOX_SOCKS_PORT=10443 SINGBOX_TROJAN_PORT=8444 bash $0 install
  sudo bash $0 status
  sudo bash $0 uninstall
EOF
}

main() {
    case "${1:-help}" in
        install)        install_singbox ;;
        uninstall|remove|purge) uninstall_singbox ;;
        status)         status_singbox ;;
        help|-h|--help) usage ;;
        *) err "Unknown command: $1"; echo; usage; exit 1 ;;
    esac
}

main "$@"
