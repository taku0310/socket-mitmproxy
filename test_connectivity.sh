#!/usr/bin/env bash
# ==============================================================================
# NX502 TCP connectivity test
# ------------------------------------------------------------------------------
# Usage:   bash test_connectivity.sh [host_ip] [port]
# Default: bash test_connectivity.sh 192.168.1.100 9999
#
# Runs from the QEMU guest (Wind River Linux) to verify that the NX502 guest
# can reach the mitmproxy listener on the host. Each step prints
# [✓] / [✗] with a timestamp; failures include a short remediation hint.
# ==============================================================================

set -u

HOST_IP="${1:-192.168.1.100}"
PORT="${2:-9999}"

TOTAL=0
FAILED=0

C_OK=""
C_NG=""
C_DIM=""
C_RST=""
if [ -t 1 ]; then
    C_OK=$'\033[32m'
    C_NG=$'\033[31m'
    C_DIM=$'\033[2m'
    C_RST=$'\033[0m'
fi

ts() { date '+%Y-%m-%d %H:%M:%S'; }

ok()   { printf '%s[%s✓%s] %s\n'           "$C_DIM[$(ts)]$C_RST " "$C_OK" "$C_RST" "$*"; }
ng()   { printf '%s[%s✗%s] %s\n'           "$C_DIM[$(ts)]$C_RST " "$C_NG" "$C_RST" "$*"; FAILED=$((FAILED+1)); }
hint() { printf '       %s↳ %s%s\n'        "$C_DIM" "$*" "$C_RST"; }
info() { printf '%s %s\n'                  "$C_DIM[$(ts)]$C_RST" "$*"; }

has() { command -v "$1" >/dev/null 2>&1; }

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
if has nc; then
    if nc -z -w 3 "$HOST_IP" "$PORT" >/dev/null 2>&1; then
        ok "Port $PORT open"
        PORT_OPEN=1
    elif nc -w 3 "$HOST_IP" "$PORT" </dev/null >/dev/null 2>&1; then
        ok "Port $PORT open (BusyBox nc, -z unsupported)"
        PORT_OPEN=1
    else
        ng "Port $PORT closed or filtered on $HOST_IP"
        hint "verify mitmproxy is running: 'docker compose ps mitmproxy'"
        hint "verify host firewall allows TCP/$PORT (ufw allow $PORT/tcp)"
    fi
elif command -v bash >/dev/null 2>&1 \
     && bash -c "exec 3<>/dev/tcp/$HOST_IP/$PORT" 2>/dev/null; then
    ok "Port $PORT open (via /dev/tcp)"
    PORT_OPEN=1
    exec 3>&- 3<&- 2>/dev/null || true
else
    ng "nc not available and /dev/tcp unusable"
    hint "install netcat-openbsd or busybox-nc to run TCP probes"
fi

# ------------------------------------------------------------------ 4. JSON payload
step
PAYLOAD='{"linear_x":0.5,"angular_z":0.0,"timestamp":'"$(date +%s%3N 2>/dev/null || echo 0)"'}'

if [ "$PORT_OPEN" -ne 1 ]; then
    ng "JSON payload skipped (port not reachable)"
    hint "resolve the port check above first"
elif has nc; then
    if printf '%s\n' "$PAYLOAD" | nc -w 2 "$HOST_IP" "$PORT" >/dev/null 2>&1; then
        ok "JSON payload transmitted"
        info "payload: $PAYLOAD"
    else
        ng "JSON payload send failed"
        hint "watch mitmproxy logs: 'docker compose logs -f mitmproxy'"
    fi
elif command -v bash >/dev/null 2>&1; then
    if bash -c "exec 3<>/dev/tcp/$HOST_IP/$PORT && printf '%s\n' '$PAYLOAD' >&3 && exec 3>&-" \
        2>/dev/null; then
        ok "JSON payload transmitted (via /dev/tcp)"
        info "payload: $PAYLOAD"
    else
        ng "JSON payload send failed (via /dev/tcp)"
    fi
else
    ng "no TCP client available for payload send"
fi

# ------------------------------------------------------------------ 5. Burst (5 x 50ms)
step
BURST_COUNT=5
INTERVAL_MS=50
SLEEP_S="$(awk -v ms="$INTERVAL_MS" 'BEGIN{printf "%.3f", ms/1000}')"

if [ "$PORT_OPEN" -ne 1 ]; then
    ng "Burst test skipped (port not reachable)"
elif has nc; then
    sent=0
    for i in $(seq 1 "$BURST_COUNT"); do
        TS_NOW="$(date +%s%3N 2>/dev/null || echo 0)"
        LINX="$(awk -v i="$i" 'BEGIN{printf "%.2f", i*0.1}')"
        FRAME='{"linear_x":'"$LINX"',"angular_z":0.0,"seq":'"$i"',"timestamp":'"$TS_NOW"'}'
        if printf '%s\n' "$FRAME" | nc -w 1 "$HOST_IP" "$PORT" >/dev/null 2>&1; then
            sent=$((sent+1))
        fi
        sleep "$SLEEP_S"
    done
    if [ "$sent" -eq "$BURST_COUNT" ]; then
        ok "$BURST_COUNT continuous packets sent successfully"
    else
        ng "burst sent only $sent / $BURST_COUNT packets"
        hint "host may be dropping rapid reconnects; consider a persistent socket"
    fi
else
    ng "Burst test skipped (no nc available)"
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
