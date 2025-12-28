#!/usr/bin/env python3
"""
Single-device service stub (simulated) for Linux deployments.

- Waits for network/VPN interface (default: tun0) to have an IPv4 address.
- Posts periodic status pings to the backend (/api/ping).
- Listens for per-action TCP connections from the backend (backend -> device) and returns
  only final success or error (action itself is simulated).
- Exposes a TCP log stream endpoint that the backend can proxy to the UI (simulated).
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import signal
import socketserver
import subprocess
import sys
import threading
import time
import urllib.request


def post_json(url: str, payload: dict) -> None:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        method="POST",
        data=data,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        resp.read()


def _run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, check=True, text=True, capture_output=True)


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw in (None, ""):
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _iface_ipv4_addrs(iface: str) -> list[ipaddress.IPv4Interface]:
    out = _run(["ip", "-o", "-f", "inet", "addr", "show", "dev", iface]).stdout
    addrs: list[ipaddress.IPv4Interface] = []
    for line in out.splitlines():
        m = re.search(r"\sinet\s+(\d+\.\d+\.\d+\.\d+/\d+)\s", line)
        if not m:
            continue
        addrs.append(ipaddress.ip_interface(m.group(1)))  # type: ignore[arg-type]
    return addrs


def _iface_first_ipv4(iface: str) -> str | None:
    try:
        addrs = _iface_ipv4_addrs(iface)
    except subprocess.CalledProcessError:
        return None
    for addr in addrs:
        ip = addr.ip
        if ip.is_loopback or ip.is_link_local:
            continue
        return str(ip)
    return str(addrs[0].ip) if addrs else None


def wait_for_iface_ipv4(iface: str, timeout_s: float) -> str:
    deadline = None if timeout_s <= 0 else (time.monotonic() + timeout_s)
    last_log = 0.0
    while True:
        ip = _iface_first_ipv4(iface)
        if ip:
            return ip

        now = time.monotonic()
        if now - last_log >= 5:
            print(f"[net] waiting for {iface!r} to have an IPv4 address...")
            last_log = now

        if deadline is not None and now >= deadline:
            raise TimeoutError(f"timed out waiting for {iface!r} to have an IPv4 address")
        time.sleep(1)


class Device:
    def __init__(
        self,
        vin: str,
        backend_base: str,
        reported_ip: str,
        bind_host: str,
        action_port: int,
        log_port: int,
        ping_interval_s: float,
        jsonpath: str,
        report_iface: str | None,
    ) -> None:
        self.vin = vin
        self.backend_base = backend_base.rstrip("/")
        self.reported_ip: str | None = reported_ip
        self.bind_host = bind_host
        self.action_port = action_port
        self.log_port = log_port
        self.ping_interval_s = ping_interval_s
        self.jsonpath = jsonpath
        self.report_iface = report_iface
        self._action_count = 0
        self._lock = threading.Lock()
        self._service_version = self._read_service_version()
        self._build_id = os.environ.get("VO_BUILD_ID") or None
        self._updater_version = os.environ.get("VO_UPDATER_VERSION") or None

    def _read_service_version(self) -> str | None:
        base = os.path.dirname(os.path.abspath(__file__))
        for candidate in (os.path.join(base, "VERSION"), os.path.join(base, "version.txt")):
            try:
                with open(candidate, "r", encoding="utf-8") as f:
                    v = f.read().strip()
                return v or None
            except FileNotFoundError:
                continue
        return None

    def _refresh_reported_ip_if_needed(self) -> None:
        if not self.report_iface:
            return
        current = _iface_first_ipv4(self.report_iface)
        self.reported_ip = current

    def post_ping_loop(self) -> None:
        last_wait_log = 0.0
        while True:
            if self.report_iface:
                self._refresh_reported_ip_if_needed()
                if not self.reported_ip:
                    now = time.monotonic()
                    if now - last_wait_log >= 5:
                        print(f"[net] {self.report_iface!r} has no IPv4 address yet; delaying POST ping")
                        last_wait_log = now
                    time.sleep(1)
                    continue

            payload = {
                "vin": self.vin,
                "ip-address": self.reported_ip,
                "state": "not implemented",
                "data": {
                    "jsonpath": self.jsonpath,
                    "actionPort": self.action_port,
                    "logPort": self.log_port,
                    "version": {
                        "serviceVersion": self._service_version,
                        "buildId": self._build_id,
                        "updaterVersion": self._updater_version,
                    },
                },
            }

            try:
                post_json(f"{self.backend_base}/api/ping", payload)
            except Exception as exc:
                print(f"[{self.vin}] ping failed: {exc}")
            time.sleep(self.ping_interval_s)

    def handle_action(self, requested_ip: str) -> dict:
        with self._lock:
            self._action_count += 1
            action_n = self._action_count
        if action_n % 2 == 1:
            return {"ok": False, "error": "Unable to write destination file (simulated)"}
        return {"ok": True}

    def initial_log_lines(self) -> list[str]:
        now = time.time()
        return [
            f"[{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(now - 3600))}] {self.vin} last-hour log (simulated) begin",
            f"[{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(now - 30))}] {self.vin} recent log line",
            f"[{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(now))}] {self.vin} live stream start",
        ]


class ActionTCPHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        device: Device = self.server.device  # type: ignore[attr-defined]
        raw = self.rfile.readline().decode("utf-8", errors="replace").strip()
        try:
            msg = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            out = {"ok": False, "error": "invalid json"}
            self.wfile.write((json.dumps(out) + "\n").encode("utf-8"))
            return
        requested_ip = msg.get("ip", "")
        print(f"[{device.vin}] action received: ip={requested_ip!r}")
        out = device.handle_action(requested_ip)
        print(f"[{device.vin}] action result: {out}")
        self.wfile.write((json.dumps(out) + "\n").encode("utf-8"))


class LogTCPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        device: Device = self.server.device  # type: ignore[attr-defined]
        peer = f"{self.client_address[0]}:{self.client_address[1]}"
        print(f"[{device.vin}] logs client connected: {peer}")
        try:
            for line in device.initial_log_lines():
                self.request.sendall((line + "\n").encode("utf-8"))
            while True:
                time.sleep(1)
                line = f"[{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}] {device.vin} heartbeat"
                self.request.sendall((line + "\n").encode("utf-8"))
        except (BrokenPipeError, ConnectionResetError):
            return
        finally:
            print(f"[{device.vin}] logs client disconnected: {peer}")


class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


def serve_device(device: Device) -> None:
    try:
        action_server = ThreadingTCPServer((device.bind_host, device.action_port), ActionTCPHandler)
        action_server.device = device  # type: ignore[attr-defined]
        log_server = ThreadingTCPServer((device.bind_host, device.log_port), LogTCPHandler)
        log_server.device = device  # type: ignore[attr-defined]
    except OSError as exc:
        print(f"[net] failed to bind TCP servers on {device.bind_host}:{device.action_port}/{device.log_port}: {exc}")
        print("[net] if you are also running the multi-vehicle simulator, set --bind-host auto (default) or change ports")
        raise

    threading.Thread(target=action_server.serve_forever, daemon=True).start()
    threading.Thread(target=log_server.serve_forever, daemon=True).start()
    threading.Thread(target=device.post_ping_loop, daemon=True).start()


def _handle_exit(signum: int, _frame) -> None:  # type: ignore[no-untyped-def]
    raise KeyboardInterrupt


def cmd_run(args: argparse.Namespace) -> int:
    report_iface = None if args.report_ip else args.report_iface

    if args.report_ip:
        reported_ip = args.report_ip
    else:
        try:
            reported_ip = wait_for_iface_ipv4(args.report_iface, args.wait_timeout_s)
        except TimeoutError as exc:
            print(f"[net] {exc}")
            return 2

    if args.bind_host in {"auto", "reported", ""}:
        bind_host = reported_ip
    else:
        bind_host = args.bind_host

    jsonpath = args.jsonpath or f"/opt/{args.vin.lower()}/properties.json"
    print(
        f"Device starting vin={args.vin!r} -> {args.backend} (ip-address {reported_ip}, bind {bind_host}, jsonpath {jsonpath})"
    )

    signal.signal(signal.SIGINT, _handle_exit)
    signal.signal(signal.SIGTERM, _handle_exit)

    try:
        device = Device(
            vin=args.vin,
            backend_base=args.backend,
            reported_ip=reported_ip,
            bind_host=bind_host,
            action_port=args.action_port,
            log_port=args.log_port,
            ping_interval_s=args.ping_interval_s,
            jsonpath=jsonpath,
            report_iface=report_iface,
        )
        serve_device(device)
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print("Device exiting")
        return 0


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd")

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--backend", default="http://localhost:3100", help="Backend base URL")
    common.add_argument("--vin", required=True, help="Device VIN to report")
    common.add_argument("--action-port", type=int, default=9000, help="TCP port for action endpoint")
    common.add_argument("--log-port", type=int, default=9100, help="TCP port for log endpoint")
    common.add_argument("--bind-host", default="auto", help="Host/IP to bind TCP servers on (auto = reported ip-address)")
    common.add_argument("--report-iface", default="tun0", help="Interface whose IPv4 address is reported as ip-address")
    common.add_argument("--report-ip", default=None, help="Override reported ip-address (skips iface wait)")
    common.add_argument(
        "--wait-timeout-s",
        type=float,
        default=0,
        help="Seconds to wait for report-iface to get an IPv4 address (0 = forever)",
    )
    common.add_argument(
        "--ping-interval-s",
        type=float,
        default=_env_float("VO_PING_INTERVAL_S", 10.0),
        help="POST ping interval in seconds",
    )
    common.add_argument("--jsonpath", default=None, help="Value sent as data.jsonpath in POST pings")

    p_run = sub.add_parser("run", help="Run device service", parents=[common])
    p_run.set_defaults(func=cmd_run)

    # Back-compat: allow running without explicit subcommand (treated as `run`)
    if len(sys.argv) >= 2 and sys.argv[1] != "run":
        sys.argv.insert(1, "run")
    if len(sys.argv) == 1:
        sys.argv.append("run")

    args = parser.parse_args()
    func = getattr(args, "func", None)
    if func is None:
        parser.print_help()
        raise SystemExit(2)
    raise SystemExit(func(args))


if __name__ == "__main__":
    main()
