"""Bounded disposable oneshot; used only by the registered Linux baseline."""
import json
import os
from pathlib import Path
import sys
import time

root = Path(__file__).parent


def identity():
    return {"pid": os.getpid(), "uid": os.getuid(), "euid": os.geteuid(),
            "gid": os.getgid(), "egid": os.getegid(), "groups": os.getgroups()}


(root / "started.json").write_text(json.dumps(identity()))
# Leave time for controller task setup before the blocking manual start.
time.sleep(30)
(root / "completed.json").write_text(json.dumps(dict(identity(), exit_code=int(sys.argv[1]))))
raise SystemExit(int(sys.argv[1]))
