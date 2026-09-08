"""Molecule-only systemd credential metadata probe; never read its contents."""
import errno
import json
import os
from pathlib import Path
import stat
import struct


def _acl(path):
    getxattr = getattr(os, "getxattr", None)
    if getxattr is None:
        return None
    try:
        raw = getxattr(path, "system.posix_acl_access", follow_symlinks=False)
    except OSError as error:
        if error.errno in {errno.ENODATA, errno.ENOTSUP, errno.EOPNOTSUPP}:
            return None
        raise
    if len(raw) < 4 or (len(raw) - 4) % 8 or struct.unpack_from("<I", raw)[0] != 2:
        raise ValueError("credential ACL is malformed")
    return [
        {"tag": tag, "permissions": permissions, "id": identifier}
        for tag, permissions, identifier in (
            struct.unpack_from("<HHI", raw, offset)
            for offset in range(4, len(raw), 8)
        )
    ]


def metadata(path):
    info = path.lstat()
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if stat.S_ISDIR(info.st_mode):
        flags |= os.O_DIRECTORY
    descriptor = os.open(path, flags)
    try:
        read_only = bool(os.fstatvfs(descriptor).f_flag & os.ST_RDONLY)
    finally:
        os.close(descriptor)
    return {"uid": info.st_uid, "gid": info.st_gid,
            "mode": format(stat.S_IMODE(info.st_mode), "04o"),
            "regular": stat.S_ISREG(info.st_mode),
            "directory": stat.S_ISDIR(info.st_mode),
            "links": info.st_nlink, "acl": _acl(path),
            "filesystem_readonly": read_only}


if __name__ == "__main__":
    directory = Path(os.environ["CREDENTIALS_DIRECTORY"])
    credential = directory / "cloudflare-token"
    print(json.dumps({"process_uid": os.geteuid(), "process_gid": os.getegid(),
                      "credential": metadata(credential), "parent": metadata(directory),
                      "credential_root": metadata(directory.parent)}, sort_keys=True))
