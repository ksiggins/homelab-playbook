"""Strict public policy and bounded, descriptor-anchored file reads."""
from dataclasses import dataclass
import errno
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import struct

LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
DOMAIN = re.compile(rf"{LABEL}(?:\.{LABEL})+")
ACL_USER_OBJ = 0x01
ACL_USER = 0x02
ACL_GROUP_OBJ = 0x04
ACL_GROUP = 0x08
ACL_MASK = 0x10
ACL_OTHER = 0x20
ACL_UNDEFINED_ID = 0xFFFFFFFF
_ACL_TAGS = {ACL_USER_OBJ, ACL_USER, ACL_GROUP_OBJ, ACL_GROUP, ACL_MASK, ACL_OTHER}


@dataclass(frozen=True)
class Policy:
    namespace: str
    email: str
    reader_gid: int
    endpoints: list

    @property
    def sans(self):
        return ["*." + self.namespace]


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate policy field")
        result[key] = value
    return result


def parse_policy(raw):
    obj = json.loads(raw, object_pairs_hook=_unique)
    if not isinstance(obj, dict) or set(obj) != {"namespace", "email", "reader_gid", "endpoints"}:
        raise ValueError("policy fields do not match approved schema")
    namespace = obj["namespace"]
    if (not isinstance(namespace, str) or len(namespace) > 240
            or not namespace.startswith("infra.") or not DOMAIN.fullmatch(namespace[6:])):
        raise ValueError("namespace must be infra beneath the operator's domain")
    email = obj["email"]
    if (not isinstance(email, str) or len(email) > 254
            or not re.fullmatch(r"[a-zA-Z0-9_.+%-]+@[a-z0-9.-]+", email)
            or not DOMAIN.fullmatch(email.split("@")[1])):
        raise ValueError("invalid ACME contact email")
    gid = obj["reader_gid"]
    if type(gid) is not int or not 1 <= gid < 2**31:
        raise ValueError("reader_gid must be an explicit positive numeric group")
    endpoints = obj["endpoints"]
    if not isinstance(endpoints, list) or not 1 <= len(endpoints) <= 32:
        raise ValueError("declare one to 32 TLS endpoints")
    seen = set()
    for endpoint in endpoints:
        if not isinstance(endpoint, dict) or set(endpoint) != {"hostname", "address", "port"}:
            raise ValueError("invalid endpoint fields")
        hostname = endpoint["hostname"]
        if (not isinstance(hostname, str)
                or not re.fullmatch(rf"{LABEL}\.{re.escape(namespace)}", hostname)
                or hostname in seen):
            raise ValueError("endpoint hostname must be unique and directly beneath namespace")
        seen.add(hostname)
        address = endpoint["address"]
        if not isinstance(address, str) or "%" in address:
            raise ValueError("endpoint address must be a private IP literal")
        ip = ipaddress.ip_address(address)
        if (not ip.is_private or ip.is_loopback or ip.is_unspecified
                or ip.is_multicast or ip.is_link_local):
            raise ValueError("endpoint address must be a private unicast listener")
        if type(endpoint["port"]) is not int or not 1 <= endpoint["port"] <= 65535:
            raise ValueError("invalid endpoint port")
    return Policy(namespace, email, gid, endpoints)


def secure_path(path, owner_uid=0, directory=False):
    """Check a trusted absolute path, including every ancestor; never resolve links."""
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("expected fixed absolute path")
    for ancestor in reversed(path.parents):
        info = ancestor.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("unsafe trusted parent directory")
    info = path.lstat()
    valid_type = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if (not valid_type or info.st_uid != owner_uid or info.st_mode & 0o022
            or (not directory and info.st_nlink != 1)):
        raise ValueError("unsafe trusted path")
    return info


def read_posix_acl(descriptor, attribute="system.posix_acl_access"):
    """Return a Linux POSIX ACL from an already opened descriptor."""
    getxattr = getattr(os, "getxattr", None)
    if getxattr is None:
        return None
    try:
        raw = getxattr(descriptor, attribute)
    except OSError as error:
        if error.errno in (errno.ENODATA, errno.ENOTSUP, errno.EOPNOTSUPP):
            return None
        raise
    if len(raw) < 4 or (len(raw) - 4) % 8 or struct.unpack_from("<I", raw)[0] != 2:
        raise ValueError("POSIX ACL is malformed")
    entries = tuple(
        struct.unpack_from("<HHI", raw, offset)
        for offset in range(4, len(raw), 8)
    )
    if any(tag not in _ACL_TAGS for tag, _permissions, _identifier in entries):
        raise ValueError("POSIX ACL is malformed")
    return entries


def require_no_named_access_acl(descriptor):
    entries = read_posix_acl(descriptor)
    if entries is not None and any(
            entry[0] in (ACL_USER, ACL_GROUP) for entry in entries):
        raise ValueError("named POSIX access ACL is not permitted")


def require_no_default_acl(descriptor):
    if read_posix_acl(descriptor, "system.posix_acl_default") is not None:
        raise ValueError("POSIX default ACL is not permitted")


def read_bounded(root, relative, owner_uid, maximum, *, expected_gid=None,
                 expected_mode=None, reject_named_acl=False):
    """Anchor reads below a previously checked root; issuer paths may be hostile."""
    parts = str(relative).split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise ValueError("invalid relative input path")
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            if info.st_uid != owner_uid or info.st_mode & 0o022:
                raise ValueError("unsafe input directory")
        source = os.open(parts[-1], os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=fd)
        try:
            before = os.fstat(source)
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                    or before.st_uid != owner_uid or before.st_mode & 0o022
                    or (expected_gid is not None and before.st_gid != expected_gid)
                    or (expected_mode is not None
                        and stat.S_IMODE(before.st_mode) != expected_mode)
                    or before.st_size > maximum):
                raise ValueError("unsafe certificate input metadata")
            if reject_named_acl:
                require_no_named_access_acl(source)
            chunks = []
            size = 0
            while True:
                chunk = os.read(source, min(65536, maximum + 1 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
                if size > maximum:
                    raise ValueError("input exceeds size limit")
            after = os.fstat(source)
            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                    after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise ValueError("input changed during snapshot")
            return b"".join(chunks)
        finally:
            os.close(source)
    finally:
        os.close(fd)
