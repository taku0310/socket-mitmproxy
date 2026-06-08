#!/usr/bin/env bash
# ==============================================================================
# NX502 TCP connectivity test
# ------------------------------------------------------------------------------
# Usage:   bash test_connectivity.sh [host_ip] [port]
# Default: bash test_connectivity.sh 192.168.1.100 9999
#
# Runs from the QEMU guest (Wind River Linux) to verify that the guest can
# reach the mitmproxy listener on the host. Each step prints [✓] / [✗]
# with a timestamp; failures include short remediation hints.
#
# BusyBox-safe: falls back to /dev/tcp when nc is missing, /proc/uptime when
# date %3N is unavailable, and an integer-second sleep when fractional sleep
# is rejected.
# ==============================================================================

set -u

HOST_IP="${1:-192.168.1.100}"
PORT="${2:-9999}"

TOTAL=0
FAILED=0

C_OK=""; C_NG=""; C_DIM=""; C_RST=""
if [ -t 1 ]; then
    C_OK=$'\033[32m'; C_NG=$'\033[31m'
    C_DIM=$'\033[2m'; C_RST=$'\033[0m'
fi

ts()   { date '+%Y-%m-%d %H:%M:%S'; }

ms_ts() {
    # GNU date %3N → milliseconds. BusyBox date treats it literally.
    local out
    out="$(date +%s%3N 2>/dev/null || echo)"
    case "$out" in
        ''|*N|*'%3N') echo "$(date +%s 2>/dev/null || echo 0)000" ;;
        *)            echo "$out" ;;
    esac
}

nap_50ms() {
    # 50 ms sleep with portable fallbacks.
    if sleep 0.05 2>/dev/null; then return 0; fi
    if command -v usleep >/dev/null 2>&1; then usleep 50000; return 0; fi
    sleep 1
}

ok()   { printf '%s[%s✓%s] %s\n' "$C_DIM[$(ts)]$C_RST " "$C_OK" "$C_RST" "$*"; }
ng()   { printf '%s[%s✗%s] %s\n' "$C_DIM[$(ts)]$C_RST " "$C_NG" "$C_RST" "$*"; FAILED=$((FAILED+1)); }
hint() { printf '       %s↳ %s%s\n' "$C_DIM" "$*" "$C_RST"; }
info() { printf '%s %s\n' "$C_DIM[$(ts)]$C_RST" "$*"; }

has()  { command -v "$1" >/dev/null 2>&1; }
step() { TOTAL=$((TOTAL+1)); }

# ------------------------------------------------------------------ header
echo "=== NX502 TCP Connectivity Check ==="
echo "Host:      ${HOST_IP}:${PORT}"
echo "Timestamp: $(ts)"
echo

# ------------------------------------------------------------------ 1. Guest IP
step
GUEST_IP=""
if has ip; then
    GUEST_IP="$(ip -4 -o addr show scope global 2>/dev/null \
                | awk '{print $4}' | cut -d/ -f1 | head -n1)"
elif has hostname; then
    GUEST_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
elif has ifconfig; then
    GUEST_IP="$(ifconfig 2>/dev/null \
                | awk '/inet (addr:)?[0-9]+\./ && $2 !~ /127\./ {
                        sub(/addr:/,"",$2); print $2; exit }')"
fi

if [ -n "$GUEST_IP" ]; then
    ok "Guest IP: $GUEST_IP"
else
    ng "Guest IP: not detected"
    hint "install iproute2 or run 'ip addr' manually to inspect interfaces"
fi

# ------------------------------------------------------------------ 2. Ping host
step
if has ping; then
    if PING_OUT="$(ping -c 3 -W 2 "$HOST_IP" 2>&1)"; then
        LOSS="$(printf '%s\n' "$PING_OUT" \
                | awk -F',' '/packet loss/ {for(i=1;i<=NF;i++) if($i~/loss/) print $i}' \
                | awk '{print $1}' | tr -d ' ')"
        [ -z "$LOSS" ] && LOSS="0%"
        ok "Host reachable (${LOSS} loss)"
    else
        ng "Host $HOST_IP not reachable via ICMP"
        hint "check guest route: 'ip route' / firewall on host (ufw, iptables)"
        hint "verify host and guest are on the same L2 segment (e.g. virbr0)"
    fi
else
    ng "ping not available"
    hint "install iputils-ping or use 'nc -zv' as a fallback"
fi

# ------------------------------------------------------------------ 3. TCP port
step
PORT_OPEN=0
NC_KIND=""
if has nc; then
    if nc -z -w 3 "$HOST_IP" "$PORT" >/dev/null 2>&1; then
        ok "Port $PORT open"
        PORT_OPEN=1; NC_KIND="z"
    elif nc -w 3 "$HOST_IP" "$PORT" </dev/null >/dev/null 2>&1; then
        ok "Port $PORT open (BusyBox nc, -z unsupported)"
        PORT_OPEN=1; NC_KIND="plain"
    else
        ng "Port $PORT closed or filtered on $HOST_IP"
        hint "verify mitmproxy is running: 'docker compose ps mitmproxy'"
        hint "verify host firewall allows TCP/$PORT (ufw allow $PORT/tcp)"
    fi
elif bash -c "exec 3<>/dev/tcp/$HOST_IP/$PORT" 2>/dev/null; then
    ok "Port $PORT open (via /dev/tcp)"
    PORT_OPEN=1; NC_KIND="devtcp"
    exec 3>&- 3<&- 2>/dev/null || true
else
    ng "nc not available and /dev/tcp unusable"
    hint "install netcat-openbsd or busybox-nc to run TCP probes"
fi

send_tcp() {
    # send_tcp <body-from-stdin>; returns 0 on apparent success.
    local body
    body="$(cat)"
    case "$NC_KIND" in
        z|plain) printf '%s' "$body" | nc -w 3 "$HOST_IP" "$PORT" >/dev/null 2>&1 ;;
        devtcp)  bash -c "
                    exec 3<>/dev/tcp/$HOST_IP/$PORT &&
                    printf '%s' \"\$0\" >&3 &&
                    exec 3>&-
                 " "$body" 2>/dev/null ;;
        *)       return 1 ;;
    esac
}

# ------------------------------------------------------------------ 4. JSON payload
step
PAYLOAD='{"linear_x":0.5,"angular_z":0.0,"timestamp":'"$(ms_ts)"'}'

if [ "$PORT_OPEN" -ne 1 ]; then
    ng "JSON payload skipped (port not reachable)"
    hint "resolve the port check above first"
else
    if printf '%s\n' "$PAYLOAD" | send_tcp; then
        ok "JSON payload transmitted"
        info "payload: $PAYLOAD"
    else
        ng "JSON payload send failed"
        hint "watch mitmproxy logs: 'docker compose logs -f mitmproxy'"
    fi
fi

# ------------------------------------------------------------------ 5. Burst (5 x 50ms over a single connection)
step
if [ "$PORT_OPEN" -ne 1 ]; then
    ng "Burst test skipped (port not reachable)"
else
    BURST_TMP="$(mktemp 2>/dev/null || echo "/tmp/burst.$$")"
    : > "$BURST_TMP"
    sent=0
    for i in 1 2 3 4 5; do
        TS_NOW="$(ms_ts)"
        LINX="$(awk -v i="$i" 'BEGIN{printf "%.2f", i*0.1}')"
        printf '{"linear_x":%s,"angular_z":0.0,"seq":%d,"timestamp":%s}\n' \
            "$LINX" "$i" "$TS_NOW" >> "$BURST_TMP"
        sent=$((sent+1))
        [ "$i" -lt 5 ] && nap_50ms
    done

    if send_tcp < "$BURST_TMP"; then
        ok "$sent continuous packets sent over a single connection"
    else
        ng "burst send failed (sent buffer: $sent frames)"
        hint "check that mitmproxy upstream (sink) is healthy"
    fi
    rm -f "$BURST_TMP"
fi

# ------------------------------------------------------------------ summary
echo
if [ "$FAILED" -eq 0 ]; then
    echo "=== All checks passed (${TOTAL}/${TOTAL}) ==="
    exit 0
else
    PASSED=$((TOTAL - FAILED))
    echo "=== ${FAILED} check(s) failed (${PASSED}/${TOTAL} passed) ==="
    exit 1
fi
