#!/usr/bin/env bash
set -euo pipefail

# ==========================================================
#   TeaTun  —  by Teejay
#   A fast point-to-point ICMP tunnel manager for 2 servers.
#   https://github.com/GreatTeejay/TeaTun
# ==========================================================

BINARY="/usr/local/bin/teatun"
BINARY_URL="${BINARY_URL:-https://github.com/GreatTeejay/teatun/releases/latest/download/teatun}"
SCRIPT_DIR="$(cd "$(dirname "$(realpath "$0" 2>/dev/null || echo "$PWD")")" 2>/dev/null && pwd || echo "$PWD")"
CONFIG_DIR="/etc/teatun"
SERVICE_TEMPLATE="/etc/systemd/system/teatun@.service"
NETRULES_BIN="/usr/local/sbin/teatun-netrules"
FORWARDS_LIST="${CONFIG_DIR}/forwards.list"
FORWARDS_BIN="/usr/local/sbin/teatun-forwards"
FORWARDS_UNIT="/etc/systemd/system/teatun-forwards.service"
ABUSE_URL="${ABUSE_URL:-https://raw.githubusercontent.com/Kiya6955/Abuse-Defender/main/abuse-ips.ipv4}"
ABUSE_CACHE="${CONFIG_DIR}/abuse-ips.list"
ABUSE_WL="${CONFIG_DIR}/abuse-whitelist.list"
ABUSE_WL_USER="${CONFIG_DIR}/abuse-whitelist-user.list"
ABUSE_BIN="/usr/local/sbin/teatun-abuse"
ABUSE_UNIT="/etc/systemd/system/teatun-abuse.service"
PING_SYSCTL="/etc/sysctl.d/99-teatun-ping.conf"
INSTALL_MARK="${CONFIG_DIR}/.sysctl-applied"

RED='\033[0;31m';   GREEN='\033[0;32m';  YELLOW='\033[1;33m'
CYAN='\033[0;36m';  BLUE='\033[0;34m';   MAGENTA='\033[0;35m'
BOLD='\033[1m';     DIM='\033[2m';       RESET='\033[0m'

info()  { echo -e "  ${GREEN}✔${RESET} $*"; }
warn()  { echo -e "  ${YELLOW}▲${RESET} $*"; }
error() { echo -e "  ${RED}✖${RESET} $*" >&2; }
ask()   { echo -en "  ${BOLD}${CYAN}➜${RESET} ${BOLD}$*${RESET} "; }
die()   { error "$*"; exit 1; }
hr() { echo -e "  ${DIM}────────────────────────────────────────────${RESET}"; }

banner() {
    echo ""
    echo -e "${BOLD}${CYAN}  _____ _____ _____ _____ _   _ _   _ ${RESET}"
    echo -e "${BOLD}${CYAN} |_   _| ____|  _  |_   _| | | | \\ | |${RESET}"
    echo -e "${BOLD}${CYAN}   | | |  _| | |_| | | | | | | |  \\| |${RESET}"
    echo -e "${BOLD}${CYAN}   | | | |___|  _  | | | | |_| | |\\  |${RESET}"
    echo -e "${BOLD}${CYAN}   |_| |_____|_| |_| |_|  \\___/|_| \\_|${RESET}"
    echo ""
    echo -e "        ${DIM}fast ICMP tunnel · ${RESET}${BOLD}${MAGENTA}by Teejay${RESET}"
    echo -e "        ${DIM}github.com/GreatTeejay/TeaTun${RESET}"
    echo ""
}

download() {
    local url="$1" out="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL -o "$out" "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$out" "$url"
    else
        return 1
    fi
}

[[ $EUID -eq 0 ]] || die "Run as root."

# ----------------------------------------------------------------------------
# dependencies, binary, systemd unit, kernel tuning
# ----------------------------------------------------------------------------

ensure_deps() {
    local missing=()
    for pkg in iproute2 iptables procps kmod curl ca-certificates conntrack; do
        dpkg -s "$pkg" &>/dev/null || missing+=("$pkg")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        info "Installing required packages: ${missing[*]}"
        DEBIAN_FRONTEND=noninteractive apt-get update -y
        DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing[@]}" \
            || die "apt-get failed to install: ${missing[*]}"
    fi
}

ensure_binary() {
    ensure_deps

    local candidates=(
        "${SCRIPT_DIR}/teatun"
        "${SCRIPT_DIR}/dist/teatun"
        "${SCRIPT_DIR}/teatun-linux-amd64"
        "${SCRIPT_DIR}/flagtun"
        "/root/teatun"
        "/root/flagtun"
    )
    local newbin="" updated=0
    for c in "${candidates[@]}"; do
        [[ -f "$c" ]] && { newbin="$c"; break; }
    done

    if [[ -n "$newbin" ]]; then
        install -m 755 "$newbin" "$BINARY"
        updated=1
        info "Installed/updated binary from ${newbin}"
        case "$newbin" in
            /root/*) rm -f "$newbin" && info "Removed staged copy ${newbin}" ;;
        esac
    elif [[ ! -f "$BINARY" ]]; then
        info "Downloading teatun binary from ${BINARY_URL}"
        download "$BINARY_URL" "$BINARY" || die "Could not download binary. Set BINARY_URL=<url> or place teatun next to this script."
        chmod +x "$BINARY"
        updated=1
    fi

    mkdir -p "$CONFIG_DIR"
    install_netrules_helper
    install_service_template
    systemctl daemon-reload
    [[ -f /etc/systemd/journald.conf.d/99-teatun.conf ]] || cap_journal

    # Tune the host once, automatically, on first install.
    if [[ ! -f "$INSTALL_MARK" ]]; then
        ensure_sysctl
        touch "$INSTALL_MARK"
    fi
    info "ICMP TUN installed."

    if [[ "$updated" == 1 ]]; then
        local running
        running=$(systemctl list-units --state=active --no-legend 'teatun@*.service' 2>/dev/null | awk '{print $1}')
        if [[ -n "$running" ]]; then
            ask "Binary updated. Restart running tunnels onto it now? [Y/n]:"; read -r _ans
            if [[ "${_ans,,}" != "n" ]]; then
                # shellcheck disable=SC2086
                systemctl restart $running && info "Restarted: $(echo $running | tr '\n' ' ')"
            fi
        fi
    fi
}

# The per-tunnel network rules. This is where the old script had its worst bug:
# the unit applied iptables rules against %i (the *tunnel name*, e.g.
# "iran-19001") while the actual interface is the *tun device* (e.g. "tun1").
# The rules attached to a non-existent interface and silently never matched.
# This helper reads the real device out of the config and applies the rules to
# it, so forwarding, NAT and MSS-clamping actually take effect.
install_netrules_helper() {
    cat > "$NETRULES_BIN" << 'NRULES'
#!/usr/bin/env bash
# usage: teatun-netrules <start|stop> <tunnel-name>
action="${1:-}"; name="${2:-}"
cfg="/etc/teatun/${name}.toml"
[[ -f "$cfg" ]] || exit 0

val() { grep -E "^$1[[:space:]]*=" "$cfg" 2>/dev/null | head -1 \
        | sed -E 's/^[^=]*=[[:space:]]*//; s/^"([^"]*)".*/\1/; s/[[:space:]]*#.*$//; s/[[:space:]]*$//'; }

dev="$(val tun_name)"
[[ -n "$dev" ]] || exit 0

# ICMP carries the tunnel; keep it out of conntrack on this host (idempotent,
# left in place across restarts — harmless and wanted on a tunnel node).
for hook in PREROUTING OUTPUT; do
    iptables -t raw -C "$hook" -p icmp -j NOTRACK 2>/dev/null \
        || iptables -t raw -A "$hook" -p icmp -j NOTRACK 2>/dev/null || true
done

add() { iptables "$@" 2>/dev/null || true; }
ensure() {  # ensure a rule exists exactly once: -C then -A
    local table="$1"; shift
    if [[ "$table" == "filter" ]]; then
        iptables -C "$@" 2>/dev/null || iptables -A "$@" 2>/dev/null || true
    else
        iptables -t "$table" -C "$@" 2>/dev/null || iptables -t "$table" -A "$@" 2>/dev/null || true
    fi
}
drop() {
    local table="$1"; shift
    if [[ "$table" == "filter" ]]; then
        while iptables -D "$@" 2>/dev/null; do :; done
    else
        while iptables -t "$table" -D "$@" 2>/dev/null; do :; done
    fi
}

case "$action" in
  start)
    ensure filter FORWARD -i "$dev" -j ACCEPT
    ensure filter FORWARD -o "$dev" -j ACCEPT
    ensure nat POSTROUTING -o "$dev" -j MASQUERADE
    # Clamp TCP MSS on transit traffic so sessions through the tunnel do not
    # black-hole on the smaller tunnel MTU.
    ensure mangle FORWARD -o "$dev" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    ensure mangle FORWARD -i "$dev" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    ;;
  stop)
    drop filter FORWARD -i "$dev" -j ACCEPT
    drop filter FORWARD -o "$dev" -j ACCEPT
    drop nat POSTROUTING -o "$dev" -j MASQUERADE
    drop mangle FORWARD -o "$dev" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    drop mangle FORWARD -i "$dev" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    ;;
  *) exit 0 ;;
esac
NRULES
    chmod +x "$NETRULES_BIN"
}

install_service_template() {
    mkdir -p "$(dirname "$SERVICE_TEMPLATE")"
    cat > "$SERVICE_TEMPLATE" << 'SVCEOF'
[Unit]
Description=ICMP TUN tunnel: %i
After=network-online.target
Wants=network-online.target

[Service]
Type=simple

# Per-tunnel iptables (reads the real tun device from the config).
ExecStartPre=-/usr/local/sbin/teatun-netrules start %i
ExecStart=/usr/local/bin/teatun -config /etc/teatun/%i.toml
ExecStopPost=-/usr/local/sbin/teatun-netrules stop %i

Restart=always
RestartSec=3
LimitNOFILE=1048576
LimitMEMLOCK=infinity
LogRateLimitIntervalSec=30s
LogRateLimitBurst=200
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
SVCEOF
}

ensure_sysctl() {
    local mem_kb mem_mb sockbuf conntrack buckets
    mem_kb=$(awk '/^MemTotal/ {print $2; exit}' /proc/meminfo 2>/dev/null)
    [[ -z "$mem_kb" || ! "$mem_kb" =~ ^[0-9]+$ ]] && mem_kb=1048576
    mem_mb=$(( mem_kb / 1024 ))

    sockbuf=$(( mem_kb * 1024 / 16 ))
    (( sockbuf < 16777216  )) && sockbuf=16777216
    (( sockbuf > 134217728 )) && sockbuf=134217728

    conntrack=$(( mem_kb * 1024 / 16384 ))
    (( conntrack < 65536   )) && conntrack=65536
    (( conntrack > 2000000 )) && conntrack=2000000
    buckets=$(( conntrack / 4 ))

    modprobe nf_conntrack 2>/dev/null || true

    cat > /etc/sysctl.d/99-teatun.conf << SYSEOF
net.core.rmem_max = ${sockbuf}
net.core.wmem_max = ${sockbuf}
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.core.optmem_max = 2097152
net.core.default_qdisc = fq
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 300000
net.core.netdev_budget = 1000
net.core.netdev_budget_usecs = 8000
net.ipv4.tcp_rmem = 4096 131072 ${sockbuf}
net.ipv4.tcp_wmem = 4096 131072 ${sockbuf}
net.ipv4.udp_rmem_min = 131072
net.ipv4.udp_wmem_min = 131072
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_notsent_lowat = 131072
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_max_tw_buckets = 2000000
net.ipv4.tcp_syn_retries = 3
net.ipv4.tcp_synack_retries = 3
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
net.ipv4.ping_group_range = 0 2147483647
net.ipv4.ip_forward = 1
net.netfilter.nf_conntrack_max = ${conntrack}
net.netfilter.nf_conntrack_buckets = ${buckets}
net.netfilter.nf_conntrack_tcp_be_liberal = 1
net.netfilter.nf_conntrack_tcp_timeout_established = 7200
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 30
vm.swappiness = 10
fs.file-max = 2097152
fs.nr_open = 2097152
SYSEOF

    sysctl -p /etc/sysctl.d/99-teatun.conf >/dev/null 2>&1 || true
    info "host sysctl applied  (RAM=${mem_mb}MB  sock_buf_max=$(( sockbuf / 1024 / 1024 ))MB  conntrack_max=${conntrack})"
}

cap_journal() {
    mkdir -p /etc/systemd/journald.conf.d
    cat > /etc/systemd/journald.conf.d/99-teatun.conf << 'EOF'
[Journal]
SystemMaxUse=200M
SystemMaxFileSize=50M
RuntimeMaxUse=100M
MaxRetentionSec=7day
EOF
    systemctl restart systemd-journald 2>/dev/null || true
    info "journal capped (200M on disk, 7-day retention)"
}

# ----------------------------------------------------------------------------
# config helpers
# ----------------------------------------------------------------------------

toml_get() {
    local file="$1" key="$2"
    grep -E "^${key}\s*=" "$file" 2>/dev/null | head -1 \
        | sed 's/.*=\s*//; s/^"\([^"]*\)".*/\1/; s/[[:space:]]*#.*$//; s/[[:space:]]*$//'
}

list_tunnels() {
    local found=()
    if [[ -d "$CONFIG_DIR" ]]; then
        for f in "$CONFIG_DIR"/*.toml; do
            [[ -f "$f" ]] && found+=("$(basename "$f" .toml)")
        done
    fi
    echo "${found[@]+${found[@]}}"
}

next_tun_name() {
    local -A used=()
    while IFS= read -r iface; do
        [[ -n "$iface" ]] && used["$iface"]=1
    done < <(ip -o link show | awk -F': ' '{print $2}')
    if [[ -d "$CONFIG_DIR" ]]; then
        for f in "$CONFIG_DIR"/*.toml; do
            [[ -f "$f" ]] || continue
            local n; n=$(toml_get "$f" "tun_name")
            [[ -n "$n" ]] && used["$n"]=1
        done
    fi
    local i=1
    while [[ -n "${used["tun${i}"]:-}" ]]; do
        (( i++ )); (( i > 65535 )) && die "No free tun device name."
    done
    echo "tun${i}"
}

next_tun_subnet() {
    local used=()
    if [[ -d "$CONFIG_DIR" ]]; then
        for f in "$CONFIG_DIR"/*.toml; do
            [[ -f "$f" ]] || continue
            local tun oct
            tun=$(toml_get "$f" "local_tun")
            oct=$(echo "$tun" | sed -nE 's/^[0-9]+\.[0-9]+\.([0-9]+)\..*/\1/p')
            [[ -n "$oct" ]] && used+=("$oct")
        done
    fi
    local i=1
    while true; do
        local taken=false
        for u in "${used[@]+${used[@]}}"; do [[ "$u" == "$i" ]] && taken=true && break; done
        $taken || break
        (( i++ )); (( i > 254 )) && die "No free TUN subnet in 155.155.x.0/24."
    done
    echo "$i"
}

next_health_port() {
    local used=()
    if [[ -d "$CONFIG_DIR" ]]; then
        for f in "$CONFIG_DIR"/*.toml; do
            [[ -f "$f" ]] || continue
            local p; p=$(toml_get "$f" "health_port")
            [[ -n "$p" ]] && used+=("$p")
        done
    fi
    local p=19001
    while true; do
        local taken=false
        for u in "${used[@]+${used[@]}}"; do [[ "$u" == "$p" ]] && taken=true && break; done
        $taken || break
        (( p++ )); (( p > 65535 )) && die "No free health port."
    done
    echo "$p"
}

# icmp_id must be identical on both ends. Derive a stable default from the
# unordered pair of endpoint IPs, so both servers compute the same value
# without the operator having to copy it across by hand.
suggest_icmp_id() {
    local a="$1" b="$2" lo hi h
    if [[ "$a" < "$b" ]]; then lo="$a"; hi="$b"; else lo="$b"; hi="$a"; fi
    h=$(printf '%s|%s' "$lo" "$hi" | cksum | cut -d' ' -f1)
    echo $(( 1025 + (h % 60000) ))
}

id_in_use() {
    local id="$1" f n
    for f in "$CONFIG_DIR"/*.toml; do
        [[ -f "$f" ]] || continue
        n=$(toml_get "$f" "icmp_id")
        [[ "$n" == "$id" ]] && return 0
    done
    return 1
}

default_iface() { ip route show default | awk '/default/ {print $5; exit}'; }

default_local_ip() {
    local iface; iface=$(default_iface)
    [[ -z "$iface" ]] && echo "" && return
    ip -4 addr show dev "$iface" | awk '/inet / {split($2,a,"/"); print a[1]; exit}'
}

# ----------------------------------------------------------------------------
# create tunnel
# ----------------------------------------------------------------------------

cmd_create() {
    [[ -f "$BINARY" ]] || die "teatun binary not found."
    mkdir -p "$CONFIG_DIR"

    echo ""
    echo -e "  ${BOLD}${CYAN}New tunnel${RESET}"
    hr
    echo -e "   ${BOLD}1)${RESET} IRAN     ${DIM}(server side)${RESET}"
    echo -e "   ${BOLD}2)${RESET} KHAREJ   ${DIM}(client side)${RESET}"
    echo ""
    ask "Choose [1/2]:"; read -r side_choice
    local side mode
    case "$side_choice" in
        1) side="iran";   mode="server" ;;
        2) side="kharej"; mode="client" ;;
        *) die "Invalid choice." ;;
    esac

    local suggested_port; suggested_port=$(next_health_port)
    ask "Health port [${suggested_port}]:"; read -r health_port
    health_port="${health_port:-${suggested_port}}"
    if ! [[ "$health_port" =~ ^[0-9]+$ ]] || (( health_port < 1 || health_port > 65535 )); then
        die "health_port must be 1-65535"
    fi

    local suggested_name="${side}-${health_port}"
    ask "Tunnel name [${suggested_name}]:"; read -r tunnel_name
    tunnel_name="${tunnel_name:-${suggested_name}}"
    [[ "$tunnel_name" =~ ^[A-Za-z0-9_-]+$ ]] || die "tunnel_name must be alphanumeric/dash/underscore"
    local cfg_file="$CONFIG_DIR/${tunnel_name}.toml"

    if [[ -f "$cfg_file" ]]; then
        warn "Config already exists: $cfg_file"
        ask "Overwrite? [y/N]:"; read -r ans
        [[ "${ans,,}" == "y" ]] || return
    fi

    info "Tunnel: $tunnel_name  (service: teatun@${tunnel_name})"

    local detected_local_ip; detected_local_ip=$(default_local_ip)
    ask "Local IP [${detected_local_ip}]:"; read -r local_ip
    local_ip="${local_ip:-${detected_local_ip}}"
    [[ -z "$local_ip" ]] && die "Local IP cannot be empty."

    ask "Remote IP (the other server's public IP):"; read -r remote_ip
    [[ -z "$remote_ip" ]] && die "Remote IP cannot be empty."

    local oct; oct=$(next_tun_subnet)
    local default_local_tun default_peer_tun
    if [[ "$side" == "iran" ]]; then
        default_local_tun="155.155.${oct}.1/24"; default_peer_tun="155.155.${oct}.2/24"
    else
        default_local_tun="155.155.${oct}.2/24"; default_peer_tun="155.155.${oct}.1/24"
    fi

    ask "Local TUN IP/mask [${default_local_tun}]:"; read -r local_tun
    local_tun="${local_tun:-${default_local_tun}}"

    ask "Peer TUN IP/mask [${default_peer_tun}]:"; read -r peer_tun
    peer_tun="${peer_tun:-${default_peer_tun}}"

    local suggested_tun; suggested_tun=$(next_tun_name)
    ask "TUN device name [${suggested_tun}]:"; read -r tun_name
    tun_name="${tun_name:-$suggested_tun}"

    # Deterministic, matches on both ends for the same IP pair.
    local suggested_icmp icmp_id
    suggested_icmp=$(suggest_icmp_id "$local_ip" "$remote_ip")
    if id_in_use "$suggested_icmp"; then
        warn "icmp_id ${suggested_icmp} already used here; pick a value and set the SAME on the peer."
    fi
    ask "ICMP id (MUST match the other end) [${suggested_icmp}]:"; read -r icmp_id
    icmp_id="${icmp_id:-$suggested_icmp}"
    { [[ "$icmp_id" =~ ^[0-9]+$ ]] && (( icmp_id >= 1 && icmp_id <= 65535 )); } || die "icmp_id must be 1-65535"

    local mtu=1320 v
    ask "MTU [${mtu}]:"; read -r v; mtu="${v:-$mtu}"
    { [[ "$mtu" =~ ^[0-9]+$ ]] && (( mtu >= 576 && mtu <= 9000 )); } || die "mtu must be 576-9000"

    local workers gomaxprocs=0 sock_buf_bytes=0
    local tun_write_queue_depth=0 tun_write_workers=0 tx_queue_len=0
    local log_level=info stats_interval_secs=30
    local icmp_send_type icmp_recv_type
    workers=$(nproc)
    [[ "$mode" == "client" ]] && icmp_send_type=8 || icmp_send_type=0
    [[ "$mode" == "client" ]] && icmp_recv_type=0 || icmp_recv_type=8

    echo ""
    echo -e "  ${BOLD}${CYAN}Performance profile${RESET}"
    hr
    echo -e "   ${BOLD}1)${RESET} gaming      ${DIM}ultra-low latency, RTT-critical   (busy-poll 100µs)${RESET}"
    echo -e "   ${BOLD}2)${RESET} latency     ${DIM}low latency / interactive         (busy-poll 50µs)${RESET}"
    echo -e "   ${BOLD}3)${RESET} balanced    ${DIM}sensible mix (default)${RESET}"
    echo -e "   ${BOLD}4)${RESET} throughput  ${DIM}high-bandwidth bulk${RESET}"
    echo -e "   ${BOLD}5)${RESET} extreme     ${DIM}maximum throughput, pushed hard${RESET}"
    echo -e "   ${BOLD}6)${RESET} custom      ${DIM}set the knobs yourself${RESET}"
    echo ""
    ask "Profile [1-6, default 3]:"; read -r profile_choice
    profile_choice="${profile_choice:-3}"

    local profile busy_poll_us dscp so_priority recv_batch_size tun_qdisc
    case "$profile_choice" in
        1) profile=gaming;     busy_poll_us=100; dscp=46; so_priority=7; recv_batch_size=32;   tun_qdisc=fq_codel ;;
        2) profile=latency;    busy_poll_us=50;  dscp=46; so_priority=7; recv_batch_size=64;   tun_qdisc=fq_codel ;;
        3) profile=balanced;   busy_poll_us=0;   dscp=0;  so_priority=6; recv_batch_size=256;  tun_qdisc=fq ;;
        4) profile=throughput; busy_poll_us=0;   dscp=0;  so_priority=6; recv_batch_size=1024; tun_qdisc=fq ;;
        5) profile=extreme;    busy_poll_us=0;   dscp=0;  so_priority=0; recv_batch_size=2048; tun_qdisc=fq ;;
        6)
            profile=custom; busy_poll_us=0; dscp=0; so_priority=6; recv_batch_size=256; tun_qdisc=fq
            echo ""
            echo -e "  ${BOLD}${CYAN}Custom profile knobs${RESET}"
            hr
            ask "busy_poll_us (0-10000) [${busy_poll_us}]:";      read -r v; busy_poll_us="${v:-$busy_poll_us}"
            ask "dscp (0-63) [${dscp}]:";                         read -r v; dscp="${v:-$dscp}"
            ask "so_priority (0-7) [${so_priority}]:";            read -r v; so_priority="${v:-$so_priority}"
            ask "recv_batch_size (1-4096) [${recv_batch_size}]:"; read -r v; recv_batch_size="${v:-$recv_batch_size}"
            ask "tun_qdisc (fq|fq_codel|cake|pfifo_fast|pfifo|sfq|noqueue) [${tun_qdisc}]:"; read -r v; tun_qdisc="${v:-$tun_qdisc}"
            { [[ "$busy_poll_us" =~ ^[0-9]+$ ]] && (( busy_poll_us <= 10000 )); }        || die "busy_poll_us 0-10000"
            { [[ "$dscp" =~ ^[0-9]+$ ]] && (( dscp <= 63 )); }                           || die "dscp 0-63"
            { [[ "$so_priority" =~ ^[0-9]+$ ]] && (( so_priority <= 7 )); }              || die "so_priority 0-7"
            { [[ "$recv_batch_size" =~ ^[0-9]+$ ]] && (( recv_batch_size >= 1 && recv_batch_size <= 4096 )); } || die "recv_batch_size 1-4096"
            case "$tun_qdisc" in fq|fq_codel|cake|pfifo_fast|pfifo|sfq|noqueue) ;; *) die "tun_qdisc invalid" ;; esac
            ;;
        *) die "Invalid profile choice (1-6)." ;;
    esac
    info "Profile: ${profile}  busy_poll=${busy_poll_us}µs dscp=${dscp} sopri=${so_priority} recv_batch=${recv_batch_size} qdisc=${tun_qdisc}  workers=${workers}"

    cat > "$cfg_file" << TOMLEOF
tunnel_name = "${tunnel_name}"
mode        = "${mode}"
local_ip    = "${local_ip}"
remote_ip   = "${remote_ip}"

local_tun   = "${local_tun}"
peer_tun    = "${peer_tun}"
tun_name    = "${tun_name}"
mtu         = ${mtu}
tun_qdisc   = "${tun_qdisc}"

health_port = ${health_port}
transport   = "icmp"

log_level           = "${log_level}"
stats_interval_secs = ${stats_interval_secs}

gomaxprocs            = ${gomaxprocs}
workers               = ${workers}
tun_write_queue_depth = ${tun_write_queue_depth}
tun_write_workers     = ${tun_write_workers}
tx_queue_len          = ${tx_queue_len}

icmp_id        = ${icmp_id}
icmp_send_type = ${icmp_send_type}
icmp_recv_type = ${icmp_recv_type}
sock_buf_bytes = ${sock_buf_bytes}

busy_poll_us    = ${busy_poll_us}
dscp            = ${dscp}
so_priority     = ${so_priority}
recv_batch_size = ${recv_batch_size}
TOMLEOF

    info "Config written to $cfg_file"

    systemctl enable "teatun@${tunnel_name}" 2>/dev/null
    systemctl restart "teatun@${tunnel_name}"
    sleep 1
    systemctl status "teatun@${tunnel_name}" --no-pager -l || true
    echo ""
    info "Now create the matching tunnel on the OTHER server with icmp_id=${icmp_id}."
}

# ----------------------------------------------------------------------------
# port forwarding (iptables DNAT)
# ----------------------------------------------------------------------------

forwards_install_helper() {
    cat > "$FORWARDS_BIN" << 'HLP'
#!/usr/bin/env bash
LIST="/etc/teatun/forwards.list"
sysctl -wq net.ipv4.ip_forward=1 2>/dev/null || true
iptables -t nat -N TEATUN_PRE  2>/dev/null || iptables -t nat -F TEATUN_PRE
iptables -t nat -N TEATUN_POST 2>/dev/null || iptables -t nat -F TEATUN_POST
iptables        -N TEATUN_FWD  2>/dev/null || iptables        -F TEATUN_FWD
iptables -t nat -C PREROUTING  -j TEATUN_PRE  2>/dev/null || iptables -t nat -A PREROUTING  -j TEATUN_PRE
iptables -t nat -C POSTROUTING -j TEATUN_POST 2>/dev/null || iptables -t nat -A POSTROUTING -j TEATUN_POST
while iptables -D FORWARD -j TEATUN_FWD 2>/dev/null; do :; done
iptables -I FORWARD 1 -j TEATUN_FWD
iptables -A TEATUN_FWD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
[[ -f "$LIST" ]] || exit 0
while read -r proto lport dip dport; do
    [[ -z "$proto" || "$proto" == \#* ]] && continue
    iptables -t nat -A TEATUN_PRE  -p "$proto" --dport "$lport" -j DNAT --to-destination "${dip}:${dport}"
    iptables -t nat -A TEATUN_POST -p "$proto" -d "$dip" --dport "$dport" -j MASQUERADE
    iptables        -A TEATUN_FWD  -p "$proto" -d "$dip" --dport "$dport" -j ACCEPT
done < "$LIST"
HLP
    chmod +x "$FORWARDS_BIN"
    cat > "$FORWARDS_UNIT" << 'UNIT'
[Unit]
Description=ICMP TUN port forwards
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/teatun-forwards
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload || true
    systemctl enable teatun-forwards.service 2>/dev/null || true
}

forwards_apply() {
    forwards_install_helper
    if "$FORWARDS_BIN"; then
        info "Forwards applied ($(grep -cvE '^[[:space:]]*(#|$)' "$FORWARDS_LIST" 2>/dev/null || echo 0) rule(s))."
    else
        warn "Applying forwards failed."
    fi
}

forward_add() {
    local proto lport dest dip dport
    ask "Protocol [tcp/udp, default tcp]:"; read -r proto
    proto="${proto:-tcp}"
    case "$proto" in tcp|udp) ;; *) warn "proto must be tcp or udp"; return ;; esac
    ask "Local port to listen on:"; read -r lport
    if ! [[ "$lport" =~ ^[0-9]+$ ]] || (( lport < 1 || lport > 65535 )); then warn "bad local port"; return; fi
    ask "Destination IP:PORT (e.g. 155.155.1.2:443):"; read -r dest
    if [[ -z "$dest" || ! "$dest" =~ ^[^:]+:[0-9]+$ ]]; then warn "bad destination (need IP:PORT)"; return; fi
    dip="${dest%%:*}"; dport="${dest##*:}"
    if awk '{print $1" "$2}' "$FORWARDS_LIST" 2>/dev/null | grep -qx "$proto $lport"; then
        warn "${proto} port ${lport} already forwarded"; return
    fi
    echo "${proto} ${lport} ${dip} ${dport}" >> "$FORWARDS_LIST"
    info "Added ${proto} :${lport} -> ${dip}:${dport}"
    forwards_apply
}

forward_remove() {
    local -a shown=()
    local proto lport dip dport idx=1
    echo ""
    echo -e "  ${BOLD}Current forwards:${RESET}"
    while read -r proto lport dip dport; do
        [[ -z "$proto" || "$proto" == \#* ]] && continue
        echo -e "   ${BOLD}${idx})${RESET} ${proto} :${lport} ${CYAN}->${RESET} ${dip}:${dport}"
        shown+=("${proto} ${lport} ${dip} ${dport}")
        (( idx++ ))
    done < "$FORWARDS_LIST"
    (( ${#shown[@]} == 0 )) && { warn "no forwards to remove"; return; }
    ask "Remove which #:"; read -r sel
    if ! [[ "$sel" =~ ^[0-9]+$ ]] || (( sel < 1 || sel > ${#shown[@]} )); then warn "invalid"; return; fi
    local target="${shown[$(( sel - 1 ))]}"
    grep -vxF "$target" "$FORWARDS_LIST" > "${FORWARDS_LIST}.tmp" 2>/dev/null && mv "${FORWARDS_LIST}.tmp" "$FORWARDS_LIST"
    info "Removed: ${target}"
    forwards_apply
    local rproto rlport rdip rdport
    read -r rproto rlport rdip rdport <<< "$target"
    if command -v conntrack >/dev/null 2>&1; then
        conntrack -D -p "$rproto" -d "$rdip" --dport "$rdport" 2>/dev/null || true
        conntrack -D -p "$rproto" --dport "$rlport" 2>/dev/null || true
    fi
}

forward_flush_all() {
    ask "Remove ALL forwards? [y/N]:"; read -r a
    [[ "${a,,}" == "y" ]] || return
    : > "$FORWARDS_LIST"
    iptables -t nat -F TEATUN_PRE  2>/dev/null || true
    iptables -t nat -F TEATUN_POST 2>/dev/null || true
    iptables        -F TEATUN_FWD  2>/dev/null || true
    command -v conntrack >/dev/null 2>&1 && conntrack -F 2>/dev/null || true
    info "All forwards removed."
}

cmd_forward() {
    mkdir -p "$CONFIG_DIR"
    touch "$FORWARDS_LIST"
    forwards_apply

    while true; do
        echo ""
        echo -e "  ${BOLD}${CYAN}Port forwards${RESET} ${DIM}(iptables DNAT)${RESET}"
        hr
        local i=1 any=0 proto lport dip dport
        while read -r proto lport dip dport; do
            [[ -z "$proto" || "$proto" == \#* ]] && continue
            echo -e "   ${BOLD}${i})${RESET} ${proto} :${lport} ${CYAN}->${RESET} ${dip}:${dport}"
            any=1; (( i++ ))
        done < "$FORWARDS_LIST"
        (( any == 0 )) && echo -e "   ${DIM}(none yet)${RESET}"
        echo ""
        echo -e "   ${BOLD}a)${RESET} add     ${BOLD}r)${RESET} remove     ${BOLD}f)${RESET} flush ALL     ${BOLD}0)${RESET} back"
        echo ""
        ask "Choose:"; read -r c
        case "$c" in
            a|A) forward_add ;;
            r|R) forward_remove ;;
            f|F) forward_flush_all ;;
            0)   return ;;
            *)   warn "invalid option" ;;
        esac
    done
}

# ----------------------------------------------------------------------------
# abuse defender
# ----------------------------------------------------------------------------

abuse_install_helper() {
    cat > "$ABUSE_BIN" << 'HLP'
#!/usr/bin/env bash
CACHE="/etc/teatun/abuse-ips.list"
WL="/etc/teatun/abuse-whitelist.list"
iptables -N TEATUN_ABUSE 2>/dev/null || iptables -F TEATUN_ABUSE
while iptables -D OUTPUT -j TEATUN_ABUSE 2>/dev/null; do :; done
iptables -I OUTPUT 1 -j TEATUN_ABUSE
if [[ -f "$WL" ]]; then
    while read -r ip; do [[ -z "$ip" || "$ip" == \#* ]] && continue; iptables -A TEATUN_ABUSE -d "$ip" -j ACCEPT 2>/dev/null; done < "$WL"
fi
if [[ -f "$CACHE" ]]; then
    while read -r ip; do [[ -z "$ip" || "$ip" == \#* ]] && continue; iptables -A TEATUN_ABUSE -d "$ip" -j DROP 2>/dev/null; done < "$CACHE"
fi
HLP
    chmod +x "$ABUSE_BIN"
    cat > "$ABUSE_UNIT" << 'UNIT'
[Unit]
Description=ICMP TUN abuse defender
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/teatun-abuse
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload || true
    systemctl enable teatun-abuse.service 2>/dev/null || true
}

abuse_regen_whitelist() {
    {
        echo "127.0.0.0/8"
        echo "155.155.0.0/16"
        local f
        for f in "$CONFIG_DIR"/*.toml; do
            [[ -f "$f" ]] && toml_get "$f" remote_ip
        done
        [[ -f "$ABUSE_WL_USER" ]] && cat "$ABUSE_WL_USER"
        true
    } | grep -vE '^[[:space:]]*$' | sort -u > "$ABUSE_WL" || true
}

abuse_enable() {
    info "Fetching abuse IP list..."
    if download "$ABUSE_URL" "${ABUSE_CACHE}.tmp" && [[ -s "${ABUSE_CACHE}.tmp" ]]; then
        grep -E '^[0-9]' "${ABUSE_CACHE}.tmp" > "$ABUSE_CACHE" || true
        rm -f "${ABUSE_CACHE}.tmp"
    else
        rm -f "${ABUSE_CACHE}.tmp"
        [[ -f "$ABUSE_CACHE" ]] || { warn "could not fetch list and no cache present"; return 0; }
        warn "fetch failed — using cached list"
    fi
    if ! [[ -s "$ABUSE_CACHE" ]]; then
        warn "abuse list is empty (source may be unreachable) — nothing applied"
        return 0
    fi
    abuse_regen_whitelist
    abuse_install_helper
    if "$ABUSE_BIN"; then
        info "Abuse defender ON  ($(grep -cE '^[0-9]' "$ABUSE_CACHE" 2>/dev/null || echo 0) ranges blocked; tunnel peers whitelisted)"
    fi
}

abuse_disable() {
    while iptables -D OUTPUT -j TEATUN_ABUSE 2>/dev/null; do :; done
    iptables -F TEATUN_ABUSE 2>/dev/null || true
    iptables -X TEATUN_ABUSE 2>/dev/null || true
    systemctl disable teatun-abuse.service 2>/dev/null || true
    info "Abuse defender OFF."
}

abuse_whitelist_add() {
    local ip
    ask "IP or CIDR to always allow (e.g. 1.2.3.4 or 1.2.3.0/24):"; read -r ip
    [[ -z "$ip" ]] && return
    echo "$ip" >> "$ABUSE_WL_USER"
    abuse_regen_whitelist
    [[ -x "$ABUSE_BIN" ]] && "$ABUSE_BIN" 2>/dev/null
    info "Whitelisted $ip"
}

cmd_abuse() {
    mkdir -p "$CONFIG_DIR"
    while true; do
        local status="${RED}off${RESET}"
        iptables -C OUTPUT -j TEATUN_ABUSE 2>/dev/null && status="${GREEN}on${RESET}"
        echo ""
        echo -e "  ${BOLD}${CYAN}Abuse defender${RESET}  [${status}]"
        hr
        echo -e "   ${DIM}blocks the server's outbound to known abuse/private ranges${RESET}"
        echo -e "   ${DIM}(tunnel peers + 155.155.0.0/16 are auto-whitelisted)${RESET}"
        echo ""
        echo -e "   ${BOLD}1)${RESET} enable / update list"
        echo -e "   ${BOLD}2)${RESET} disable"
        echo -e "   ${BOLD}3)${RESET} whitelist an IP/CIDR"
        echo -e "   ${BOLD}0)${RESET} back"
        echo ""
        ask "Choose:"; read -r c
        case "$c" in
            1) abuse_enable ;;
            2) abuse_disable ;;
            3) abuse_whitelist_add ;;
            0) return ;;
            *) warn "invalid option" ;;
        esac
    done
}

# ----------------------------------------------------------------------------
# manage tunnels
# ----------------------------------------------------------------------------

tunnel_health() {
    local name="$1" port
    port=$(toml_get "$CONFIG_DIR/${name}.toml" health_port)
    [[ -z "$port" ]] && { warn "no health_port in config"; return; }
    if ! command -v curl >/dev/null 2>&1; then warn "curl not installed"; return; fi
    echo ""
    curl -fsS --max-time 3 "http://127.0.0.1:${port}/stats" 2>/dev/null \
        || warn "health endpoint not responding on 127.0.0.1:${port}"
    echo ""
}

cmd_manage() {
    local tunnels
    read -ra tunnels <<< "$(list_tunnels)"
    [[ ${#tunnels[@]} -gt 0 ]] || { warn "No tunnels configured."; return; }

    echo ""
    echo -e "  ${BOLD}${CYAN}Tunnels${RESET}"
    hr
    local i=1
    for t in "${tunnels[@]}"; do
        local st
        if   systemctl is-active  "teatun@${t}" &>/dev/null; then st="${GREEN}● running${RESET}"
        elif systemctl is-enabled "teatun@${t}" &>/dev/null; then st="${YELLOW}● stopped${RESET}"
        else st="${RED}● disabled${RESET}"; fi
        echo -e "   ${BOLD}$i)${RESET} $t  [$st]"
        (( i++ ))
    done

    echo ""
    ask "Select tunnel:"; read -r sel
    if ! [[ "$sel" =~ ^[0-9]+$ ]] || (( sel < 1 || sel > ${#tunnels[@]} )); then
        warn "Invalid selection."; return
    fi
    local name="${tunnels[$(( sel - 1 ))]:-}"
    [[ -z "$name" ]] && die "Invalid selection."

    echo ""
    echo -e "  ${BOLD}${CYAN}$name${RESET}"
    hr
    echo -e "   ${BOLD}1)${RESET} restart"
    echo -e "   ${BOLD}2)${RESET} logs"
    echo -e "   ${BOLD}3)${RESET} health / stats"
    echo -e "   ${BOLD}4)${RESET} delete"
    echo ""
    ask "Action [1-4]:"; read -r action

    case "$action" in
        1)
            systemctl restart "teatun@${name}"
            info "Restarted teatun@${name}"
            ;;
        2)
            echo ""
            systemctl status "teatun@${name}" --no-pager -l || true
            echo ""
            journalctl -u "teatun@${name}" -n 50 --no-pager || true
            ;;
        3)
            tunnel_health "$name"
            ;;
        4)
            ask "Delete ${name}? [y/N]:"; read -r confirm
            if [[ "${confirm,,}" == "y" ]]; then
                systemctl stop    "teatun@${name}" 2>/dev/null || true
                systemctl disable "teatun@${name}" 2>/dev/null || true
                "$NETRULES_BIN" stop "$name" 2>/dev/null || true
                rm -f "$CONFIG_DIR/${name}.toml"
                info "Deleted $name"
            fi
            ;;
        *) warn "Invalid action." ;;
    esac
}

cmd_optimize() {
    info "Applying host tuning for $(nproc) CPU / $(( $(awk '/^MemTotal/{print $2;exit}' /proc/meminfo) / 1024 ))MB RAM..."
    ensure_sysctl
    cap_journal
    touch "$INSTALL_MARK"
    info "Done. sysctl + journal cap applied."
}

# ----------------------------------------------------------------------------
# ping control
# ----------------------------------------------------------------------------

ping_status() {
    local v
    v=$(sysctl -n net.ipv4.icmp_echo_ignore_all 2>/dev/null || echo 0)
    [[ "$v" == "1" ]] && echo blocked || echo open
}

ping_block() {
    sysctl -wq net.ipv4.icmp_echo_ignore_all=1 >/dev/null 2>&1 || sysctl -w net.ipv4.icmp_echo_ignore_all=1 >/dev/null
    echo "net.ipv4.icmp_echo_ignore_all = 1" > "$PING_SYSCTL"
    info "Ping blocked — kernel no longer auto-replies to ICMP echo. Tunnel is unaffected."
}

ping_unblock() {
    sysctl -wq net.ipv4.icmp_echo_ignore_all=0 >/dev/null 2>&1 || sysctl -w net.ipv4.icmp_echo_ignore_all=0 >/dev/null
    echo "net.ipv4.icmp_echo_ignore_all = 0" > "$PING_SYSCTL"
    info "Ping unblocked — server replies to ICMP echo (ping) again."
}

cmd_ping() {
    while true; do
        local st="${GREEN}open${RESET}"
        [[ "$(ping_status)" == "blocked" ]] && st="${RED}blocked${RESET}"
        echo ""
        echo -e "  ${BOLD}${CYAN}Ping control${RESET} ${DIM}(ICMP echo)${RESET}  [${st}]"
        hr
        echo -e "   ${DIM}blocking stops the kernel's automatic ping reply, so your${RESET}"
        echo -e "   ${DIM}uplink isn't doubled by reflected echoes on some hosts.${RESET}"
        echo -e "   ${DIM}the tunnel keeps working either way.${RESET}"
        echo ""
        echo -e "   ${BOLD}1)${RESET} Block ping"
        echo -e "   ${BOLD}2)${RESET} Unblock ping"
        echo -e "   ${BOLD}0)${RESET} back"
        echo ""
        ask "Choose:"; read -r c
        case "$c" in
            1) ping_block ;;
            2) ping_unblock ;;
            0) return ;;
            *) warn "invalid option" ;;
        esac
    done
}

# ----------------------------------------------------------------------------
# main menu
# ----------------------------------------------------------------------------

main_menu() {
    ensure_binary
    banner
    while true; do
        echo -e "  ${BOLD}${CYAN}┌──────────────────────────────────┐${RESET}"
        echo -e "  ${BOLD}${CYAN}│         ICMP TUN  manager        │${RESET}"
        echo -e "  ${BOLD}${CYAN}└──────────────────────────────────┘${RESET}"
        echo -e "  ${DIM}configs:${RESET} ${CYAN}${CONFIG_DIR}${RESET}"
        echo ""
        echo -e "   ${BOLD}1)${RESET} Create tunnel"
        echo -e "   ${BOLD}2)${RESET} Manage tunnels"
        echo -e "   ${BOLD}3)${RESET} Port forwarding ${DIM}(iptables)${RESET}"
        echo -e "   ${BOLD}4)${RESET} Optimize host ${DIM}(sysctl + sizing, RAM/CPU based)${RESET}"
        echo -e "   ${BOLD}5)${RESET} Abuse defender ${DIM}(block abuse ranges)${RESET}"
        echo -e "   ${BOLD}6)${RESET} Ping control ${DIM}(block / unblock ICMP echo)${RESET}"
        echo -e "   ${BOLD}0)${RESET} Exit"
        echo ""
        ask "Choose:"; read -r choice

        case "$choice" in
            1) cmd_create ;;
            2) cmd_manage ;;
            3) cmd_forward ;;
            4) cmd_optimize ;;
            5) cmd_abuse ;;
            6) cmd_ping ;;
            0) echo -e "  ${DIM}bye.${RESET}"; exit 0 ;;
            *) warn "Invalid option." ;;
        esac
    done
}

main_menu
