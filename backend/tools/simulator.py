#!/usr/bin/env python3
"""
Device/service simulator (non-Node) for local development.

- Posts periodic status pings to the backend (/api/ping) for multiple vehicles.
- Listens for per-action TCP connections from the backend (backend -> device) and returns
  only final success or error (no action data in POST pings).
- Exposes a per-vehicle TCP log stream endpoint that the backend can proxy to the UI.

Usage:
  # 1) One-time network setup (requires sudo)
  sudo python3 backend/tools/simulator.py net-setup

  # Optional: remove the dummy interface (requires sudo)
  sudo python3 backend/tools/simulator.py net-cleanup

  # 2) Run simulator (no sudo; uses IPs configured by net-setup)
  python3 backend/tools/simulator.py run --backend http://localhost:3100

Notes:
  - Backend is expected to use the `ip-address` reported in POST pings as the device host,
    and `deviceActionPort`/`deviceLogPort` from backend config as the ports.
  - Dummy interface mode uses addresses from `10.0.0.0/24` by default:
    - "Gateway" address: `10.0.0.1/24`
    - Per-vehicle device IPs: `10.0.0.(N)` (default start `10.0.0.11`)
    This lets the backend connect to distinct device IPs while all devices use the same ports.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import os
import sys
import re
import json
import signal
import socketserver
import subprocess
import threading
import time
import urllib.request

VEHICLES: list[tuple[str, float]] = [
    ("CAR_FAST_1", 3.0),
    ("CAR_FAST_2", 3.0),
    ("CAR_FAST_3", 5.0),
    ("CAR_FAST_4", 6.0),
    ("CAR_FAST_5", 7.0),
    ("CAR_MEDM_1", 9.0),
    ("CAR_MEDM_2", 13.0),
    ("CAR_SLOW_1", 20.0),
    ("CAR_SLOW_2", 65.0),
    ("CAR_SLOW_3", 90.0),
]

DEFAULT_DUMMY_IFACE = "vo-sim0"
DEFAULT_DUMMY_GATEWAY = "10.0.0.1"
DEFAULT_DUMMY_PREFIXLEN = 24


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


def _run_ignore_exists(cmd: list[str]) -> None:
    try:
        _run(cmd)
    except subprocess.CalledProcessError as exc:
        stderr = (exc.stderr or "").lower()
        if "file exists" in stderr or "already exists" in stderr or "already assigned" in stderr:
            return
        raise


class DummyNetwork:
    def __init__(self, iface: str, gateway_ip: str, prefixlen: int) -> None:
        self.iface = iface
        self.gateway_ip = gateway_ip
        self.prefixlen = prefixlen
        self._network = ipaddress.ip_network(f"{gateway_ip}/{prefixlen}", strict=False)

    def _require_root(self) -> None:
        if os.geteuid() != 0:
            raise PermissionError(
                "Dummy interface setup requires root (try: sudo python3 backend/tools/simulator.py ...)"
            )

    def exists(self) -> bool:
        try:
            _run(["ip", "link", "show", "dev", self.iface])
            return True
        except subprocess.CalledProcessError:
            return False

    def is_dummy(self) -> bool:
        try:
            out = _run(["ip", "-d", "link", "show", "dev", self.iface]).stdout
        except subprocess.CalledProcessError:
            return False
        return "dummy" in out.lower()

    def create(self) -> None:
        self._require_root()
        if self.exists():
            if not self.is_dummy():
                raise RuntimeError(f"Interface {self.iface!r} exists but is not a dummy interface")
            return
        _run(["ip", "link", "add", self.iface, "type", "dummy"])

    def up(self) -> None:
        self._require_root()
        _run(["ip", "link", "set", self.iface, "up"])

    def add_addr(self, ip: str) -> None:
        self._require_root()
        _run_ignore_exists(["ip", "addr", "add", f"{ip}/{self.prefixlen}", "dev", self.iface])

    def ensure_route(self, cidr: str) -> None:
        self._require_root()
        _run(["ip", "route", "replace", cidr, "dev", self.iface])

    def has_addr(self, ip: str) -> bool:
        try:
            out = _run(["ip", "-o", "addr", "show", "dev", self.iface]).stdout
        except subprocess.CalledProcessError:
            return False
        needle = f" {ip}/"
        return needle in out

    def setup(self, device_ips: list[str]) -> None:
        self.create()
        self.add_addr(self.gateway_ip)
        for ip in device_ips:
            self.add_addr(ip)
        self.up()
        self.ensure_route(self._network.with_prefixlen)

    def teardown(self) -> None:
        self._require_root()
        _run(["ip", "link", "del", self.iface])


class Vehicle:
    def __init__(
        self,
        uid: str,
        label: str,
        ping_interval_s: float,
        device_ip: str,
        action_port: int,
        log_port: int,
        backend_base: str,
    ) -> None:
        self.uid = uid
        self.label = label
        self.ping_interval_s = ping_interval_s
        self.device_ip = device_ip
        self.action_port = action_port
        self.log_port = log_port
        self.backend_base = backend_base.rstrip("/")
        self._action_count = 0
        self._lock = threading.Lock()

    def post_ping_loop(self) -> None:
        while True:
            payload = {
                "uid": self.uid,
                "label": self.label,
                "ip-address": self.device_ip,
                "state": "not implemented",
                "data": {
                    "jsonpath": f"/opt/{self.label.lower()}/properties.json",
                    "actionPort": self.action_port,
                    "logPort": self.log_port,
                },
            }
            try:
                post_json(f"{self.backend_base}/api/ping", payload)
            except Exception as exc:
                print(f"[{self.label}] ping failed: {exc}")
            time.sleep(self.ping_interval_s)

    def handle_action(self, requested_ip: str) -> dict:
        with self._lock:
            self._action_count += 1
            action_n = self._action_count
        # Alternate fail/success per vehicle for testing:
        if action_n % 2 == 1:
            return {
                "ok": False,
                "error": "Unable to write destination file (simulated)",
            }
        return {"ok": True}

    def initial_log_lines(self) -> list[str]:
        now = time.time()
        return [
            f"[{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(now - 3600))}] {self.label} last-hour log (simulated) begin",
            f"[{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(now - 30))}] {self.label} recent log line",
            f"[{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(now))}] {self.label} live stream start",
        ]


class ActionTCPHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        vehicle: Vehicle = self.server.vehicle  # type: ignore[attr-defined]
        raw = self.rfile.readline().decode("utf-8", errors="replace").strip()
        try:
            msg = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            out = {"ok": False, "error": "invalid json"}
            self.wfile.write((json.dumps(out) + "\n").encode("utf-8"))
            return
        requested_ip = msg.get("ip", "")
        print(f"[{vehicle.label}] action received: ip={requested_ip!r}")
        out = vehicle.handle_action(requested_ip)
        print(f"[{vehicle.label}] action result: {out}")
        self.wfile.write((json.dumps(out) + "\n").encode("utf-8"))


class LogTCPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        vehicle: Vehicle = self.server.vehicle  # type: ignore[attr-defined]
        peer = f"{self.client_address[0]}:{self.client_address[1]}"
        print(f"[{vehicle.label}] logs client connected: {peer}")
        try:
            for line in vehicle.initial_log_lines():
                self.request.sendall((line + "\n").encode("utf-8"))
            while True:
                time.sleep(1)
                line = f"[{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}] {vehicle.label} heartbeat"
                self.request.sendall((line + "\n").encode("utf-8"))
        except (BrokenPipeError, ConnectionResetError):
            return
        finally:
            print(f"[{vehicle.label}] logs client disconnected: {peer}")


class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


def serve_vehicle(vehicle: Vehicle) -> None:
    action_server = ThreadingTCPServer((vehicle.device_ip, vehicle.action_port), ActionTCPHandler)
    action_server.vehicle = vehicle  # type: ignore[attr-defined]
    log_server = ThreadingTCPServer((vehicle.device_ip, vehicle.log_port), LogTCPHandler)
    log_server.vehicle = vehicle  # type: ignore[attr-defined]

    threading.Thread(target=action_server.serve_forever, daemon=True).start()
    threading.Thread(target=log_server.serve_forever, daemon=True).start()
    threading.Thread(target=vehicle.post_ping_loop, daemon=True).start()


def _vehicle_device_ips(net_mode: str, gateway_ip: str, device_ip_start: int) -> list[str]:
    if net_mode == "loopback":
        return [f"127.0.0.{device_ip_start + idx}" for idx in range(len(VEHICLES))]
    dummy_base = gateway_ip.rsplit(".", 1)[0]
    return [f"{dummy_base}.{device_ip_start + idx}" for idx in range(len(VEHICLES))]

def _iface_ipv4_addrs(iface: str) -> list[ipaddress.IPv4Interface]:
    out = _run(["ip", "-o", "-f", "inet", "addr", "show", "dev", iface]).stdout
    addrs: list[ipaddress.IPv4Interface] = []
    for line in out.splitlines():
        m = re.search(r"\sinet\s+(\d+\.\d+\.\d+\.\d+/\d+)\s", line)
        if not m:
            continue
        addrs.append(ipaddress.ip_interface(m.group(1)))  # type: ignore[arg-type]
    return addrs


def _infer_dummy_network_from_iface(iface: str) -> ipaddress.IPv4Network:
    addrs = _iface_ipv4_addrs(iface)
    if not addrs:
        raise RuntimeError(f"no IPv4 addresses configured on {iface!r}")
    gateway_candidates = [a for a in addrs if int(a.ip) & 0xFF == 1]
    if not gateway_candidates:
        raise RuntimeError(f"no gateway-like .1 IPv4 address found on {iface!r}")
    # Prefer the expected default gateway if present.
    for cand in gateway_candidates:
        if str(cand.ip) == DEFAULT_DUMMY_GATEWAY:
            if cand.network.prefixlen != DEFAULT_DUMMY_PREFIXLEN:
                raise RuntimeError(
                    f"expected {DEFAULT_DUMMY_GATEWAY}/{DEFAULT_DUMMY_PREFIXLEN} on {iface!r}, found {cand.with_prefixlen}"
                )
            return cand.network
    chosen = gateway_candidates[0]
    if chosen.network.prefixlen != DEFAULT_DUMMY_PREFIXLEN:
        raise RuntimeError(
            f"expected a /{DEFAULT_DUMMY_PREFIXLEN} subnet on {iface!r}, found {chosen.with_prefixlen}"
        )
    return chosen.network


def _require_device_ips_from_iface(iface: str, network: ipaddress.IPv4Network, vehicle_count: int) -> list[str]:
    gateway_ip = str(network.network_address + 1)
    iface_addrs = _iface_ipv4_addrs(iface)
    device_ips = sorted(
        [str(a.ip) for a in iface_addrs if a.ip in network and str(a.ip) != gateway_ip],
        key=lambda s: ipaddress.IPv4Address(s),
    )
    if len(device_ips) < vehicle_count:
        raise RuntimeError(f"not enough device IPs: found {len(device_ips)}, need {vehicle_count}")
    return device_ips[:vehicle_count]


def _handle_exit(signum: int, _frame) -> None:  # type: ignore[no-untyped-def]
    raise KeyboardInterrupt


def cmd_net_setup(args: argparse.Namespace) -> int:
    device_ips = _vehicle_device_ips("dummy", DEFAULT_DUMMY_GATEWAY, args.device_ip_start)
    net = DummyNetwork(args.dummy_iface, DEFAULT_DUMMY_GATEWAY, DEFAULT_DUMMY_PREFIXLEN)
    if net.exists() and not net.is_dummy():
        raise RuntimeError(f"Interface {args.dummy_iface!r} exists but is not a dummy interface")
    try:
        net.setup(device_ips)
    except PermissionError as exc:
        print(f"[net] {exc}")
        return 2
    except subprocess.CalledProcessError as exc:
        print("[net] setup failed:")
        print(f"[net] cmd: {' '.join(exc.cmd) if isinstance(exc.cmd, list) else exc.cmd}")
        if exc.stderr:
            print(f"[net] stderr: {exc.stderr.strip()}")
        print("[net] if this is a stale/bad interface state, try:")
        print(f"  sudo python3 {__file__} net-cleanup --dummy-iface {args.dummy_iface}")
        print(f"  sudo python3 {__file__} net-setup --dummy-iface {args.dummy_iface} --device-ip-start {args.device_ip_start}")
        return 2
    print(f"[net] created/updated dummy iface {args.dummy_iface!r}")
    print(f"[net] gateway: {DEFAULT_DUMMY_GATEWAY}/{DEFAULT_DUMMY_PREFIXLEN}")
    print(f"[net] devices: {device_ips[0]} .. {device_ips[-1]}")
    print(f"[net] route: {net._network.with_prefixlen} dev {args.dummy_iface}")
    return 0


def cmd_net_cleanup(args: argparse.Namespace) -> int:
    net = DummyNetwork(args.dummy_iface, DEFAULT_DUMMY_GATEWAY, DEFAULT_DUMMY_PREFIXLEN)
    if not net.exists():
        print(f"[net] interface {args.dummy_iface!r} does not exist (nothing to do)")
        return 0
    if not net.is_dummy():
        raise RuntimeError(f"Interface {args.dummy_iface!r} exists but is not a dummy interface")
    net.teardown()
    print(f"[net] removed dummy iface {args.dummy_iface!r}")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    print(f"Simulator starting {len(VEHICLES)} vehicles -> {args.backend}")

    if args.net_mode == "dummy":
        net = DummyNetwork(args.dummy_iface, DEFAULT_DUMMY_GATEWAY, DEFAULT_DUMMY_PREFIXLEN)
        if not net.exists():
            print(f"[net] missing dummy interface {args.dummy_iface!r}")
            print("[net] run setup first:")
            print(f"  sudo python3 {__file__} net-setup --dummy-iface {args.dummy_iface}")
            return 2
        if not net.is_dummy():
            print(f"[net] interface {args.dummy_iface!r} exists but is not a dummy interface")
            return 2

        try:
            network = _infer_dummy_network_from_iface(args.dummy_iface)
        except Exception as exc:
            print(f"[net] invalid dummy interface config: {exc}")
            print("[net] run setup first:")
            print(f"  sudo python3 {__file__} net-setup --dummy-iface {args.dummy_iface} --device-ip-start {args.device_ip_start}")
            return 2

        gateway_ip = str(network.network_address + 1)
        if not net.has_addr(gateway_ip):
            print(f"[net] missing gateway IP {gateway_ip}/{network.prefixlen} on {args.dummy_iface!r}")
            print("[net] run setup first:")
            print(f"  sudo python3 {__file__} net-setup --dummy-iface {args.dummy_iface}")
            return 2
        try:
            device_ips = _require_device_ips_from_iface(args.dummy_iface, network, len(VEHICLES))
        except Exception as exc:
            print(f"[net] {exc}")
            print("[net] run setup first:")
            print(f"  sudo python3 {__file__} net-setup --dummy-iface {args.dummy_iface}")
            return 2
        print(f"[net] using subnet {network.with_prefixlen} on {args.dummy_iface!r} (gateway {gateway_ip})")
    else:
        device_ips = _vehicle_device_ips("loopback", DEFAULT_DUMMY_GATEWAY, args.device_ip_start)

    signal.signal(signal.SIGINT, _handle_exit)
    signal.signal(signal.SIGTERM, _handle_exit)

    try:
        for idx, (label, interval_s) in enumerate(VEHICLES):
            device_ip = device_ips[idx]
            uid = hashlib.sha256(label.encode("utf-8")).hexdigest()[:32]
            v = Vehicle(
                uid=uid,
                label=label,
                ping_interval_s=interval_s,
                device_ip=device_ip,
                action_port=args.action_port,
                log_port=args.log_port,
                backend_base=args.backend,
            )
            serve_vehicle(v)
            print(
                f"- {label} ({uid}): ip-address {device_ip}, action tcp {device_ip}:{args.action_port}, log tcp {device_ip}:{args.log_port}"
            )

        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print("Simulator exiting")
        return 0


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd")

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--backend", default="http://localhost:3100", help="Backend base URL")
    common.add_argument("--action-port", type=int, default=9000, help="TCP port for action endpoint")
    common.add_argument("--log-port", type=int, default=9100, help="TCP port for log endpoint")
    common.add_argument(
        "--net-mode",
        choices=["dummy", "loopback"],
        default="dummy",
        help="Addressing mode for per-vehicle device IPs",
    )
    common.add_argument("--dummy-iface", default=DEFAULT_DUMMY_IFACE, help="Dummy interface name (net-mode=dummy)")
    common.add_argument(
        "--device-ip-start",
        type=int,
        default=11,
        help="First device IP last octet (loopback: 127.0.0.<n>)",
    )

    p_setup = sub.add_parser("net-setup", help="Create/configure dummy interface (requires sudo)")
    p_setup.add_argument("--dummy-iface", default=DEFAULT_DUMMY_IFACE, help="Dummy interface name")
    p_setup.add_argument("--device-ip-start", type=int, default=11, help="First device IP last octet (10.0.0.<n>)")
    p_setup.set_defaults(func=cmd_net_setup)

    p_cleanup = sub.add_parser("net-cleanup", help="Remove dummy interface (requires sudo)")
    p_cleanup.add_argument("--dummy-iface", default=DEFAULT_DUMMY_IFACE, help="Dummy interface name")
    p_cleanup.set_defaults(func=cmd_net_cleanup)

    p_run = sub.add_parser("run", help="Run simulator (requires dummy iface to exist)", parents=[common])
    p_run.set_defaults(func=cmd_run)

    # Back-compat: allow running without explicit subcommand (treated as `run`)
    if len(sys.argv) >= 2 and sys.argv[1] not in {"run", "net-setup", "net-cleanup"}:
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
