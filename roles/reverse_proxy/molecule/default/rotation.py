#!/usr/bin/python3
"""Exercise the synthetic certificate handoff and report its exact failed stage."""

import fcntl
import grp
import json
import os
from pathlib import Path
import subprocess
import sys


LOCK_PATH = Path("/run/lock/homelab-reverse-proxy.lock")
SELECTED_PATH = Path("/etc/caddy/tls/fixture/current")
HELPER_COMMAND = ["/usr/local/libexec/homelab-reverse-proxy"]
INHERITED_LOCK_FD = 9


def _detail(result):
    value = " ".join(result.stderr.split())
    return value[:240] if value else "helper returned no diagnostic"


def rotate(
    *,
    lock_path,
    selected_path,
    target,
    helper_command,
    helper_arguments,
    uid,
    gid,
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
                return {"detail": _detail(result), "result": "failed", "stage": stage}
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
    )
    print(json.dumps(report, sort_keys=True))
    return 0 if report["result"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
