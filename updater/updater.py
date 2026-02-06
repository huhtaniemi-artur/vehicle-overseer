#!/usr/bin/env python3
"""
Pull-based updater for the target device/service.

Intended usage:
- Runs as a systemd timer (oneshot) as root.
- Pulls a per-device manifest from the backend and applies updates atomically.
- Executes update.sh from the artifact.

Backend endpoints used:
- GET  /api/device/manifest?uid=UID
- GET  /api/device/artifacts/<artifact-id>

Security note:
- The artifact bytes are decrypted, SHA256 is computed over the plaintext, and the result is compared to `manifest.artifact.sha256` (mismatch aborts the update).
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


def _read_state(path: str) -> dict | None:
    raw = _read_text(path)
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


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


APP_DIRNAME = "app"
APP_BACKUP_DIRNAME = "app.bak"
UPDATE_SCRIPT_NAME = "update.sh"
def _run_update_script(app_dir: str, env: dict[str, str]) -> None:
    script_path = os.path.join(app_dir, UPDATE_SCRIPT_NAME)
    if not os.path.isfile(script_path):
        raise ValueError(f"missing {UPDATE_SCRIPT_NAME} in artifact")
    if os.access(script_path, os.X_OK):
        cmd = [script_path]
    else:
        shell = shutil.which("bash") or shutil.which("sh")
        if not shell:
            raise RuntimeError("no shell found to run update.sh (install bash or sh)")
        cmd = [shell, script_path]
    log(f"run {UPDATE_SCRIPT_NAME}")
    proc = subprocess.run(cmd, cwd=app_dir, env=env)
    if proc.returncode != 0:
        raise RuntimeError(f"{UPDATE_SCRIPT_NAME} failed (exit {proc.returncode})")


def _replace_self(app_dir: str) -> None:
    candidate = os.path.join(app_dir, "updater.py")
    if not os.path.isfile(candidate):
        return
    current_path = os.path.realpath(sys.argv[0])
    try:
        if os.path.samefile(candidate, current_path):
            return
    except FileNotFoundError:
        pass
    tmp_path = f"{current_path}.tmp"
    shutil.copy2(candidate, tmp_path)
    os.replace(tmp_path, current_path)
    log(f"updated updater: {current_path}")


def cmd_apply(args: argparse.Namespace) -> int:
    backend = args.backend.rstrip("/")
    install_root = args.install_root
    app_dir = os.path.join(install_root, APP_DIRNAME)
    backup_dir = os.path.join(install_root, APP_BACKUP_DIRNAME)
    artifact_key = _load_artifact_key(args.artifact_key_path or _env("VO_ARTIFACT_KEY_PATH"))
    if artifact_key is None:
        raise ValueError("artifact key required (artifacts are always encrypted)")
    log(f"backend={backend} installRoot={install_root}")
    uid_path = (
        args.device_uid_path
        or _env("VO_DEVICE_UID_PATH")
        or "/etc/vehicle-overseer/device.uid"
    )
    device_uid = args.device_uid or _env("VO_DEVICE_UID") or _read_text(uid_path)
    if artifact_key is not None and not device_uid:
        raise ValueError("artifact key configured but no VO_DEVICE_UID provided")
    log(f"deviceUidPath={uid_path}")
    if not device_uid:
        raise ValueError("device UID required to fetch manifest")

    manifest_uid = urllib.parse.quote(device_uid, safe="")
    manifest_url = f"{backend}/api/device/manifest?uid={manifest_uid}"
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

    state_path = os.path.join(install_root, "state.json")
    state = _read_state(state_path)
    if not args.force and state and state.get("artifactSha256") == artifact_sha256:
        log(f"artifact {artifact_sha256} already installed; skipping")
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

    tmp_dir = tempfile.mkdtemp(prefix="vo-updater-")
    try:
        tar_path = os.path.join(tmp_dir, "artifact.tar.gz")
        with open(tar_path, "wb") as f:
            f.write(blob)

        extract_dir = os.path.join(tmp_dir, "extract")
        os.makedirs(extract_dir, exist_ok=True)
        log("extract artifact")
        _safe_extract_tar(tar_path, extract_dir)
        if not os.path.isfile(os.path.join(extract_dir, UPDATE_SCRIPT_NAME)):
            raise ValueError(f"{UPDATE_SCRIPT_NAME} missing from artifact")

        try:
            if os.path.isdir(backup_dir):
                shutil.rmtree(backup_dir, ignore_errors=True)
            if os.path.isdir(app_dir):
                shutil.move(app_dir, backup_dir)
            log(f"install app: {app_dir}")
            shutil.move(extract_dir, app_dir)
            if not _read_text(os.path.join(app_dir, "VERSION")):
                _write_text(os.path.join(app_dir, "VERSION"), version + "\n")

            env = os.environ.copy()
            env["VO_INSTALL_ROOT"] = install_root
            env["VO_APP_DIR"] = app_dir
            env["VO_APP_BACKUP"] = backup_dir
            env["VO_BACKEND"] = backend
            _run_update_script(app_dir, env)

            if os.path.isdir(backup_dir):
                shutil.rmtree(backup_dir, ignore_errors=True)
            _replace_self(app_dir)
        except Exception:
            log("warn: update failed; attempting rollback")
            if os.path.isdir(app_dir):
                shutil.rmtree(app_dir, ignore_errors=True)
            if os.path.isdir(backup_dir):
                shutil.move(backup_dir, app_dir)
            raise

        state = {
            "uid": device_uid,
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
    parser.add_argument("--backend", default=_env("VO_BACKEND", "http://localhost:3100"), help="Backend base URL")
    parser.add_argument(
        "--install-root",
        default=_env("VO_INSTALL_ROOT", "/opt/vehicle-overseer"),
        help="Install root with app/ directory",
    )
    parser.add_argument("--force", action="store_true", help="Apply even if artifact matches current")
    parser.add_argument(
        "--artifact-key-path",
        default=None,
        help="Path to base64 artifact key (or set VO_ARTIFACT_KEY_PATH)",
    )
    parser.add_argument(
        "--device-uid",
        default=_env("VO_DEVICE_UID"),
        help="Device UID for encrypted artifact downloads (or set VO_DEVICE_UID)",
    )
    parser.add_argument(
        "--device-uid-path",
        default=_env("VO_DEVICE_UID_PATH"),
        help="Path to device UID file (default: /etc/vehicle-overseer/device.uid)",
    )

    args = parser.parse_args()
    raise SystemExit(cmd_apply(args))


if __name__ == "__main__":
    main()
