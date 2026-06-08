"""
mitmproxy 11.0 addon - NX502 TCP connection monitor.

Captures TCP lifecycle events (start / end / error) and parses newline
delimited JSON payloads emitted by the NX502 controller in real time.
All output is written to stdout (PYTHONUNBUFFERED=1 in the container)
so `docker compose logs -f mitmproxy` shows events as they happen.

Environment variables:
    DISPLAY_LISTEN        - "host:port" shown in TCP START log line
                            (default: "0.0.0.0:9999").
    EXPECTED_GUEST_IP     - if set, warn when client peer IP differs.
    MAX_LINE_BYTES        - drop and warn on lines larger than this
                            (default: 1048576 = 1 MiB) to avoid OOM
                            via never-terminated frames.
    EXPECTED_INTERVAL_MS  - reported as expected RX interval in stats
                            (default: 50).
"""
from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime
from typing import Any

from mitmproxy.tcp import TCPFlow, TCPMessage


REQUIRED_FIELDS: tuple[str, ...] = ("linear_x", "angular_z")

RANGES: dict[str, tuple[float, float]] = {
    "linear_x":  (-10.0,  10.0),
    "angular_z": (-3.15,  3.15),
}

DISPLAY_LISTEN: str       = os.environ.get("DISPLAY_LISTEN", "0.0.0.0:9999")
EXPECTED_GUEST_IP: str    = os.environ.get("EXPECTED_GUEST_IP", "").strip()
MAX_LINE_BYTES: int       = max(1024, int(os.environ.get("MAX_LINE_BYTES", "1048576")))
EXPECTED_INTERVAL_MS: float = float(os.environ.get("EXPECTED_INTERVAL_MS", "50"))


def _ts() -> str:
    now = datetime.now()
    return now.strftime("%Y-%m-%d %H:%M:%S.") + f"{now.microsecond // 1000:03d}"


def _log(line: str) -> None:
    sys.stdout.write(line + "\n")
    sys.stdout.flush()


def _peer(flow: TCPFlow) -> tuple[str, str]:
    cc = flow.client_conn
    if cc.peername:
        src = f"{cc.peername[0]}:{cc.peername[1]}"
    else:
        src = "?:?"
    return src, DISPLAY_LISTEN


class FlowStats:
    __slots__ = (
        "start_ts", "last_rx_ts",
        "rx_packets", "tx_packets",
        "rx_bytes",   "tx_bytes",
        "json_ok",    "json_errors",
        "schema_errors", "range_errors", "oversize_drops",
        "rx_intervals_ms", "rx_buffer",
    )

    def __init__(self) -> None:
        self.start_ts: float        = time.time()
        self.last_rx_ts: float | None = None
        self.rx_packets: int        = 0
        self.tx_packets: int        = 0
        self.rx_bytes: int          = 0
        self.tx_bytes: int          = 0
        self.json_ok: int           = 0
        self.json_errors: int       = 0
        self.schema_errors: int     = 0
        self.range_errors: int      = 0
        self.oversize_drops: int    = 0
        self.rx_intervals_ms: list[float] = []
        self.rx_buffer: bytearray   = bytearray()


class NX502Monitor:
    def __init__(self) -> None:
        self._flows: dict[str, FlowStats] = {}

    # ------------------------------------------------------------------ hooks
    def tcp_start(self, flow: TCPFlow) -> None:
        self._flows[flow.id] = FlowStats()
        src, dst = _peer(flow)
        _log(f"[{_ts()}] 🟢 [TCP START] {src} → {dst}")

        if EXPECTED_GUEST_IP and flow.client_conn.peername:
            actual_ip = flow.client_conn.peername[0]
            if actual_ip != EXPECTED_GUEST_IP:
                _log(
                    f"[{_ts()}] ⚠️  [WARN] unexpected source IP: "
                    f"got {actual_ip}, expected {EXPECTED_GUEST_IP}"
                )

    def tcp_message(self, flow: TCPFlow) -> None:
        stats = self._flows.get(flow.id)
        if stats is None:
            stats = FlowStats()
            self._flows[flow.id] = stats

        msg: TCPMessage = flow.messages[-1]
        size = len(msg.content)

        if msg.from_client:
            now = time.time()
            if stats.last_rx_ts is not None:
                stats.rx_intervals_ms.append((now - stats.last_rx_ts) * 1000.0)
            stats.last_rx_ts = now

            stats.rx_packets += 1
            stats.rx_bytes   += size
            self._consume_inbound(stats, msg.content)
        else:
            stats.tx_packets += 1
            stats.tx_bytes   += size

    def tcp_end(self, flow: TCPFlow) -> None:
        stats = self._flows.pop(flow.id, None)
        if stats is None:
            return

        duration       = time.time() - stats.start_ts
        total_packets  = stats.rx_packets + stats.tx_packets
        total_bytes    = stats.rx_bytes   + stats.tx_bytes
        avg_interval   = (
            sum(stats.rx_intervals_ms) / len(stats.rx_intervals_ms)
            if stats.rx_intervals_ms else 0.0
        )

        _log(
            f"[{_ts()}] 🔴 [TCP END] "
            f"Duration: {duration:.2f}s | "
            f"Packets: {total_packets} | "
            f"Bytes: {total_bytes}"
        )
        _log(
            f"[{_ts()}] 📊 [STATS] "
            f"RX pkts={stats.rx_packets} ({stats.rx_bytes} B) | "
            f"TX pkts={stats.tx_packets} ({stats.tx_bytes} B) | "
            f"avg RX interval={avg_interval:.2f} ms "
            f"(expected {EXPECTED_INTERVAL_MS:.0f} ms) | "
            f"JSON ok={stats.json_ok} err={stats.json_errors} "
            f"schema={stats.schema_errors} range={stats.range_errors} "
            f"oversize={stats.oversize_drops}"
        )

        if stats.rx_buffer:
            preview = bytes(stats.rx_buffer[:64]).decode("utf-8", "replace")
            _log(
                f"[{_ts()}] ⚠️  [WARN] incomplete payload "
                f"({len(stats.rx_buffer)} B, no trailing newline): {preview!r}"
            )

    def tcp_error(self, flow: TCPFlow) -> None:
        err_obj = getattr(flow, "error", None)
        err_msg = getattr(err_obj, "msg", None) or repr(err_obj) or "unknown"
        _log(f"[{_ts()}] ❌ [ERROR] TCP: {err_msg}")

    # ---------------------------------------------------------------- payload
    def _consume_inbound(self, stats: FlowStats, data: bytes) -> None:
        stats.rx_buffer.extend(data)
        while True:
            nl = stats.rx_buffer.find(b"\n")
            if nl < 0:
                if len(stats.rx_buffer) > MAX_LINE_BYTES:
                    stats.oversize_drops += 1
                    preview = bytes(stats.rx_buffer[:64]).decode("utf-8", "replace")
                    _log(
                        f"[{_ts()}] ⚠️  [WARN] dropping oversize frame "
                        f"({len(stats.rx_buffer)} B > {MAX_LINE_BYTES} B, "
                        f"no newline): {preview!r}"
                    )
                    stats.rx_buffer.clear()
                break

            line = bytes(stats.rx_buffer[:nl]).strip()
            del stats.rx_buffer[: nl + 1]
            if line:
                self._handle_json_line(stats, line)

    def _handle_json_line(self, stats: FlowStats, line: bytes) -> None:
        try:
            text = line.decode("utf-8")
        except UnicodeDecodeError as e:
            stats.json_errors += 1
            _log(f"[{_ts()}] ❌ [ERROR] JSON DECODE: utf-8 decode failed: {e}")
            return

        try:
            payload: Any = json.loads(text)
        except json.JSONDecodeError as e:
            stats.json_errors += 1
            _log(
                f"[{_ts()}] ❌ [ERROR] JSON DECODE: {e.msg} "
                f"(line/col {e.lineno}/{e.colno}): {text!r}"
            )
            return

        _log(f"[{_ts()}] 📥 [JSON RX] {text}")

        if not isinstance(payload, dict):
            stats.schema_errors += 1
            _log(
                f"[{_ts()}] ⚠️  [WARN] payload is not a JSON object "
                f"(got {type(payload).__name__})"
            )
            return

        self._validate(stats, payload)

    def _validate(self, stats: FlowStats, payload: dict[str, Any]) -> None:
        ok = True

        for field in REQUIRED_FIELDS:
            if field not in payload:
                stats.schema_errors += 1
                _log(f"[{_ts()}] ⚠️  [WARN] missing required field: {field}")
                ok = False

        for field, (lo, hi) in RANGES.items():
            if field not in payload:
                continue
            v = payload[field]
            if isinstance(v, bool) or not isinstance(v, (int, float)):
                stats.schema_errors += 1
                _log(f"[{_ts()}] ⚠️  [WARN] {field}={v!r} is not numeric")
                ok = False
                continue
            if v < lo:
                stats.range_errors += 1
                _log(f"[{_ts()}] ⚠️  [WARN] {field}={v} out of range (min {lo})")
                ok = False
            elif v > hi:
                stats.range_errors += 1
                _log(f"[{_ts()}] ⚠️  [WARN] {field}={v} out of range (max {hi})")
                ok = False

        if ok:
            stats.json_ok += 1


def load(loader) -> None:
    _log(f"[{_ts()}] 🚀 [BOOT] NX502 mitmproxy monitor loaded")
    _log(
        f"[{_ts()}] ℹ️  [INFO] listen={DISPLAY_LISTEN} "
        f"required={list(REQUIRED_FIELDS)} ranges={RANGES} "
        f"expected_interval={EXPECTED_INTERVAL_MS:.0f}ms "
        f"max_line={MAX_LINE_BYTES} B "
        f"expected_guest_ip={EXPECTED_GUEST_IP or '(any)'}"
    )


addons = [NX502Monitor()]
