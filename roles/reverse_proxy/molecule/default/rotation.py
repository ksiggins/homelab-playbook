#!/usr/bin/python3
"""Exercise the synthetic certificate handoff and report its exact failed stage."""

import fcntl
import grp
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import time


LOCK_PATH = Path("/run/lock/homelab-reverse-proxy.lock")
SELECTED_PATH = Path("/etc/caddy/tls/fixture/current")
HELPER_COMMAND = ["/usr/local/libexec/homelab-reverse-proxy"]
INHERITED_LOCK_FD = 9


def _detail(result):
    value = " ".join(result.stderr.split())
    return value[:240] if value else "helper returned no diagnostic"


def observe_fixture():
    """Observe only disposable fixture certificates, without replaying activation."""
    base = SELECTED_PATH.parent
    fingerprints = {}
    for version in ("v1", "v2"):
        pem = (base / version / "fullchain.pem").read_text()
        fingerprints[version] = hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()

    def identify(pem):
        fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()
        return next((version for version, value in fingerprints.items() if value == fingerprint), "unrecognized")

    service_view = "unavailable"
    try:
        pid = subprocess.run(
            ["systemctl", "show", "--property=MainPID", "--value", "caddy.service"],
            capture_output=True, text=True, check=True, timeout=5,
        ).stdout.strip()
        if pid.isdigit() and int(pid) > 0:
            service_certificate = Path("/proc") / pid / "root" / SELECTED_PATH.relative_to("/") / "fullchain.pem"
            service_view = identify(service_certificate.read_text())
    except (OSError, subprocess.SubprocessError):
        pass
    context = ssl.create_default_context(cafile="/var/lib/reverse-proxy-molecule/ca.pem")
    address = socket.gethostbyname(socket.gethostname())
    samples = []
    started = time.monotonic()
    for delay in (0, 1, 4):
        time.sleep(delay)
        for hostname in ("app.example.test", "other.example.test"):
            sample = {"hostname": hostname, "elapsed_seconds": round(time.monotonic() - started, 3)}
            try:
                with socket.create_connection((address, 443), timeout=2) as connection:
                    with context.wrap_socket(connection, server_hostname=hostname) as tls:
                        fingerprint = hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()
                sample["served_version"] = next(
                    (version for version, value in fingerprints.items() if value == fingerprint),
                    "unrecognized",
                )
            except OSError as error:
                sample["error"] = type(error).__name__
            samples.append(sample)
    return {
        "selected_version": SELECTED_PATH.resolve().name,
        "service_filesystem_version": service_view,
        "fixture_versions_differ": fingerprints["v1"] != fingerprints["v2"],
        "samples": samples,
    }


def rotate(
    *,
    lock_path,
    selected_path,
    target,
    helper_command,
    helper_arguments,
    uid,
    gid,
    failure_observer=None,
):
    saved_descriptor = None
    try:
        saved_descriptor = os.dup(INHERITED_LOCK_FD)
    except OSError:
        pass
    descriptor = None
    try:
        descriptor = os.open(lock_path, os.O_RDONLY | os.O_NOFOLLOW)
        if descriptor != INHERITED_LOCK_FD:
            os.dup2(descriptor, INHERITED_LOCK_FD)
            os.close(descriptor)
            descriptor = INHERITED_LOCK_FD
        fcntl.flock(INHERITED_LOCK_FD, fcntl.LOCK_EX)

        replacement = selected_path.with_name(selected_path.name + ".next")
        try:
            os.symlink(target, replacement)
            os.lchown(replacement, uid, gid)
            os.replace(replacement, selected_path)
        except OSError:
            return {"detail": "certificate selection failed", "result": "failed", "stage": "select"}

        for stage in ("reload", "verify"):
            result = subprocess.run(
                [*helper_command, stage, *helper_arguments],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                check=False,
                pass_fds=(INHERITED_LOCK_FD,),
            )
            if result.returncode:
                report = {"detail": _detail(result), "result": "failed", "stage": stage}
                if failure_observer is not None:
                    try:
                        report["observations"] = failure_observer()
                    except Exception as error:
                        report["observation_error"] = type(error).__name__
                return report
        return {"result": "passed", "stage": "verify"}
    finally:
        if descriptor == INHERITED_LOCK_FD:
            os.close(INHERITED_LOCK_FD)
        if saved_descriptor is not None:
            os.dup2(saved_descriptor, INHERITED_LOCK_FD)
            os.close(saved_descriptor)


def main():
    report = rotate(
        lock_path=LOCK_PATH,
        selected_path=SELECTED_PATH,
        target="v2",
        helper_command=HELPER_COMMAND,
        helper_arguments=["--lock-held"],
        uid=0,
        gid=grp.getgrnam("caddy").gr_gid,
        failure_observer=observe_fixture,
    )
    print(json.dumps(report, sort_keys=True))
    return 0 if report["result"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
