# Device Sandbox Container (systemd)

Build:
- `docker build -f backend/tools/docker/Dockerfile.device-sandbox -t vo-device-sandbox .`

Run (systemd inside container typically needs `--privileged`):
- Docker Desktop (macOS/Windows): `docker run --rm -it --privileged --tmpfs /run --tmpfs /run/lock vo-device-sandbox`
- Linux host: `docker run --rm -it --privileged --cgroupns=host --tmpfs /run --tmpfs /run/lock -v /sys/fs/cgroup:/sys/fs/cgroup:rw vo-device-sandbox`
  - Note: don’t bind-mount `/sys/fs/cgroup` from non-Linux hosts (it overrides the container’s cgroup mount and systemd fails).
  - Optional (Linux only) for accessing the host backend by name: add `--add-host=host.docker.internal:host-gateway`

This image is intentionally a clean sandbox: it contains only OS + `systemd` + `python3` + `iproute2`.

Install inside the container using your backend’s initial setup endpoint (intended flow):
- (Requires your backend to expose `GET /api/srvcsetup` that returns a shell script.)
- Create a dev token on the backend host:
  - `curl -sS -X POST http://127.0.0.1:3100/api/bootstrap-token -H 'Content-Type: application/json' -d '{"kind":"dev"}'`
- Then run setup in the container:
  - `curl -fsSL "http://host.docker.internal:3100/api/srvcsetup?label=DEVICE_LABEL&token=PASTE_TOKEN" | bash`
  - or `wget -qO- "http://host.docker.internal:3100/api/srvcsetup?label=DEVICE_LABEL&token=PASTE_TOKEN" | bash`
  - If neither is present, fallback:
    - `python3 -c "import urllib.request; print(urllib.request.urlopen('http://host.docker.internal:3100/api/srvcsetup?label=DEVICE_LABEL&token=PASTE_TOKEN').read().decode('utf-8'))" | bash`

Useful checks:
- `systemctl status vehicle-overseer-device.service`
- `systemctl status vo-updater.timer`
- `journalctl -u vehicle-overseer-device.service -f`
