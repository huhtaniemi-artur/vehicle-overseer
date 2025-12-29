#!/usr/bin/env python3
"""
Pull-based updater for the target device/service.

Intended usage:
- Runs as a systemd timer (oneshot) as root.
- Pulls a per-device manifest from the backend and applies updates atomically.

Backend endpoints used:
- GET  /api/device/manifest?vin=VIN
- GET  /api/device/artifacts/<artifact-id>

Security note:
- This prototype supports optional manifest authentication via RSA-SHA256
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request

def log(msg: str) -> None:
    print(f"[updater] {msg}")


def _env(name: str, default: str | None = None) -> str | None:
    v = os.environ.get(name)
    return v if v not in (None, "") else default


def _read_text(path: str) -> str | None:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip()
    except FileNotFoundError:
        return None


def _write_text(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def _http_get_json(url: str) -> dict:
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=10) as resp:
        raw = resp.read().decode("utf-8")
    return json.loads(raw)


def _http_get_bytes(url: str) -> tuple[bytes, dict[str, str]]:
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = resp.read()
        headers = {k: v for k, v in resp.headers.items()}
        return data, headers


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _load_artifact_key(path: str | None) -> bytes | None:
    if not path:
        return None
    raw = _read_text(path)
    if not raw:
        return None
    try:
        key = base64.b64decode(raw, validate=True)
    except Exception as exc:
        raise ValueError(f"invalid base64 in artifact key file {path!r}: {exc}") from exc
    if len(key) != 32:
        raise ValueError(f"artifact key must be 32 bytes (got {len(key)})")
    return key


def _decrypt_aes_256_ctr(ciphertext: bytes, key: bytes, iv_hex: str) -> bytes:
    try:
        proc = subprocess.run(
            ["openssl", "enc", "-d", "-aes-256-ctr", "-K", key.hex(), "-iv", iv_hex],
            input=ciphertext,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("openssl not found; required for encrypted artifact downloads") from exc
    if proc.returncode != 0:
        detail = (proc.stderr or b"").decode("utf-8", errors="replace").strip()
        raise ValueError(f"artifact decrypt failed: {detail or 'decrypt failed'}")
    return proc.stdout


def _verify_manifest_signature(manifest: dict, pubkey_path: str) -> None:
    algo = manifest.get("signatureAlgo")
    sig_b64 = manifest.get("signature")
    if algo != "rsa-sha256" or not isinstance(sig_b64, str) or not sig_b64:
        raise ValueError("manifest is missing signature (expected rsa-sha256)")
    try:
        signature = base64.b64decode(sig_b64, validate=True)
    except Exception as exc:
        raise ValueError(f"invalid base64 signature: {exc}") from exc

    artifact = manifest.get("artifact") or {}
    message = f"{manifest.get('deviceId')}\n{manifest.get('version')}\n{artifact.get('sha256')}"

    with tempfile.TemporaryDirectory(prefix="vo-updater-verify-") as tmp:
        msg_path = os.path.join(tmp, "msg.txt")
        sig_path = os.path.join(tmp, "sig.bin")
        with open(msg_path, "wb") as f:
            f.write(message.encode("utf-8"))
        with open(sig_path, "wb") as f:
            f.write(signature)

        try:
            proc = subprocess.run(
                ["openssl", "dgst", "-sha256", "-verify", pubkey_path, "-signature", sig_path, msg_path],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except FileNotFoundError as exc:
            raise RuntimeError("openssl not found; install it or disable signature verification") from exc

        if proc.returncode != 0:
            detail = (proc.stdout + "\n" + proc.stderr).strip()
            raise ValueError(f"manifest signature verification failed: {detail or 'verify failed'}")


def _safe_extract_tar(tar_path: str, dest_dir: str) -> None:
    with tarfile.open(tar_path, "r:gz") as tar:
        for member in tar.getmembers():
            name = member.name
            if name.startswith("/") or name.startswith("\\"):
                raise ValueError(f"unsafe tar path: {name!r}")
            norm = os.path.normpath(name)
            if norm.startswith("..") or os.path.isabs(norm):
                raise ValueError(f"unsafe tar path: {name!r}")
            if member.issym() or member.islnk():
                raise ValueError(f"unsafe tar member (links not allowed): {name!r}")
            if member.isdev():
                raise ValueError(f"unsafe tar member (device file not allowed): {name!r}")
        try:
            tar.extractall(dest_dir, filter="data")
        except TypeError:
            tar.extractall(dest_dir)


def _systemctl(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["systemctl", *args], check=True, text=True, capture_output=True)


def _switch_symlink_atomic(link_path: str, target_path: str) -> str | None:
    prev = None
    try:
        prev = os.readlink(link_path)
    except OSError:
        prev = None

    tmp_link = f"{link_path}.tmp-{int(time.time())}"
    if os.path.lexists(tmp_link):
        os.unlink(tmp_link)
    os.symlink(target_path, tmp_link)
    os.replace(tmp_link, link_path)
    return prev


def _restart_unit(unit_name: str) -> None:
    _systemctl(["restart", unit_name])
    subprocess.run(["systemctl", "is-active", "--quiet", unit_name], check=True)

DEVICE_UNIT = "vehicle-overseer-device.service"
SYSTEMD_DIR = "/etc/systemd/system"
UNIT_FILES = (
    "vehicle-overseer-device.service",
    "vo-updater.service",
    "vo-updater.timer",
)


def _install_systemd_units(release_dir: str) -> bool:
    installed = False
    for name in UNIT_FILES:
        candidate_paths = [
            os.path.join(release_dir, name),
            os.path.join(release_dir, "systemd", name),
        ]
        src = next((p for p in candidate_paths if os.path.isfile(p)), None)
        if not src:
            continue
        dst = os.path.join(SYSTEMD_DIR, name)
        os.makedirs(SYSTEMD_DIR, exist_ok=True)
        shutil.copy2(src, dst)
        installed = True
    return installed


def _cleanup_old_releases(install_root: str, keep_version: str) -> None:
    releases_dir = os.path.join(install_root, "releases")
    try:
        entries = os.listdir(releases_dir)
    except FileNotFoundError:
        return
    for name in entries:
        if name == keep_version:
            continue
        path = os.path.join(releases_dir, name)
        if os.path.isdir(path):
            shutil.rmtree(path, ignore_errors=True)


def cmd_apply(args: argparse.Namespace) -> int:
    backend = args.backend.rstrip("/")
    vin = args.vin
    install_root = args.install_root
    artifact_key = _load_artifact_key(args.artifact_key_path or _env("VO_ARTIFACT_KEY_PATH"))
    if artifact_key is None:
        raise ValueError("artifact key required (artifacts are always encrypted)")
    log(f"backend={backend} vin={vin} installRoot={install_root}")
    uid_path = (
        args.device_uid_path
        or _env("VO_DEVICE_UID_PATH")
        or "/etc/vehicle-overseer/device.uid"
    )
    device_uid = args.device_uid or _env("VO_DEVICE_UID") or _read_text(uid_path)
    if artifact_key is not None and not device_uid:
        raise ValueError("artifact key configured but no VO_DEVICE_UID provided")
    log(f"deviceUidPath={uid_path}")

    os.makedirs(os.path.join(install_root, "releases"), exist_ok=True)

    manifest_url = f"{backend}/api/device/manifest?vin={vin}"
    log(f"fetch manifest: {manifest_url}")
    manifest = _http_get_json(manifest_url)

    version = manifest.get("version")
    artifact = manifest.get("artifact") or {}
    artifact_url = artifact.get("url")
    artifact_sha256 = artifact.get("sha256")
    if not isinstance(version, str) or not version:
        raise ValueError("manifest missing version")
    if not isinstance(artifact_url, str) or not artifact_url:
        raise ValueError("manifest missing artifact.url")
    if not isinstance(artifact_sha256, str) or not artifact_sha256:
        raise ValueError("manifest missing artifact.sha256")

    current_version = _read_text(os.path.join(install_root, "current", "VERSION"))
    if current_version == version and not args.force:
        log(f"already on version {version}; skipping")
        return 0

    full_artifact_url = urllib.parse.urljoin(f"{backend}/", artifact_url.lstrip("/"))
    sep = "&" if "?" in full_artifact_url else "?"
    full_artifact_url = f"{full_artifact_url}{sep}uid={device_uid}"
    log(f"download artifact: {full_artifact_url}")
    blob, headers = _http_get_bytes(full_artifact_url)
    enc = headers.get("X-VO-Enc") or headers.get("x-vo-enc")
    if not enc:
        raise ValueError("artifact response not encrypted")
    if enc.strip().lower() != "aes-256-ctr":
        raise ValueError(f"unsupported artifact encryption: {enc!r}")
    iv = headers.get("X-VO-Iv") or headers.get("x-vo-iv")
    if not iv:
        raise ValueError("encrypted artifact missing X-VO-Iv")
    blob = _decrypt_aes_256_ctr(blob, artifact_key, iv.strip())
    got_sha256 = _sha256_hex(blob)
    if got_sha256 != artifact_sha256:
        raise ValueError(f"artifact sha256 mismatch: expected {artifact_sha256}, got {got_sha256}")

    release_dir = os.path.join(install_root, "releases", version)
    tmp_dir = tempfile.mkdtemp(prefix="vo-updater-")
    try:
        tar_path = os.path.join(tmp_dir, "artifact.tar.gz")
        with open(tar_path, "wb") as f:
            f.write(blob)

        extract_dir = os.path.join(tmp_dir, "extract")
        os.makedirs(extract_dir, exist_ok=True)
        log("extract artifact")
        _safe_extract_tar(tar_path, extract_dir)

        if not args.dry_run:
            if os.path.exists(release_dir):
                shutil.rmtree(release_dir)
            log(f"install release: {release_dir}")
            shutil.copytree(extract_dir, release_dir)
            if not _read_text(os.path.join(release_dir, "VERSION")):
                _write_text(os.path.join(release_dir, "VERSION"), version + "\n")

            units_installed = _install_systemd_units(release_dir)
            if units_installed:
                log("install systemd units")
                try:
                    _systemctl(["daemon-reload"])
                except subprocess.CalledProcessError as exc:
                    log("warn: systemctl daemon-reload failed (systemd not running?)")
                    log("manual: systemctl daemon-reload")
                    log(f"details: {exc.stderr.strip() or exc.stdout.strip() or exc}")

            prev_target = _switch_symlink_atomic(os.path.join(install_root, "current"), release_dir)
            try:
                log("restart device service")
                _restart_unit(DEVICE_UNIT)
            except subprocess.CalledProcessError as exc:
                log(f"warn: failed to restart {DEVICE_UNIT} (systemd not running?)")
                log(f"manual: systemctl restart {DEVICE_UNIT}")
                log(f"details: {exc.stderr.strip() or exc.stdout.strip() or exc}")
            except Exception:
                if prev_target:
                    _switch_symlink_atomic(os.path.join(install_root, "current"), prev_target)
                    try:
                        _restart_unit(DEVICE_UNIT)
                    except Exception:
                        pass
                raise
            try:
                log("enable updater timer")
                _systemctl(["enable", "--now", "vo-updater.timer"])
            except subprocess.CalledProcessError as exc:
                log("warn: failed to enable updater timer (systemd not running?)")
                log("manual: systemctl enable --now vo-updater.timer")
                log(f"details: {exc.stderr.strip() or exc.stdout.strip() or exc}")
            _cleanup_old_releases(install_root, version)
            log("cleanup old releases")

            state = {
                "deviceId": vin,
                "version": version,
                "artifactSha256": artifact_sha256,
                "updatedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
            _write_text(os.path.join(install_root, "state.json"), json.dumps(state, indent=2) + "\n")
            log("update complete")
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
    return 0


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd")

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--backend", default=_env("VO_BACKEND", "http://localhost:3100"), help="Backend base URL")
    common.add_argument("--vin", default=_env("VO_VIN"), required=_env("VO_VIN") is None, help="Device ID/VIN")
    common.add_argument(
        "--install-root",
        default=_env("VO_INSTALL_ROOT", "/opt/vehicle-overseer-device"),
        help="Install root with releases/ and current/ symlink",
    )
    common.add_argument(
        "--artifact-key-path",
        default=None,
        help="Path to base64 artifact key (or set VO_ARTIFACT_KEY_PATH)",
    )
    common.add_argument(
        "--device-uid",
        default=_env("VO_DEVICE_UID"),
        help="Device UID for encrypted artifact downloads (or set VO_DEVICE_UID)",
    )
    common.add_argument(
        "--device-uid-path",
        default=_env("VO_DEVICE_UID_PATH"),
        help="Path to device UID file (default: /etc/vehicle-overseer/device.uid)",
    )

    p_apply = sub.add_parser("apply", parents=[common], help="Fetch manifest and apply if needed")
    p_apply.add_argument("--force", action="store_true", help="Apply even if version matches current")
    p_apply.add_argument("--dry-run", action="store_true", help="Download + verify only; do not install")
    p_apply.set_defaults(func=cmd_apply)

    # Back-compat: allow running without explicit subcommand (treated as `apply`)
    if len(sys.argv) >= 2 and sys.argv[1] != "apply":
        sys.argv.insert(1, "apply")
    if len(sys.argv) == 1:
        sys.argv.append("apply")

    args = parser.parse_args()
    func = getattr(args, "func", None)
    if func is None:
        parser.print_help()
        raise SystemExit(2)
    raise SystemExit(func(args))


if __name__ == "__main__":
    main()
