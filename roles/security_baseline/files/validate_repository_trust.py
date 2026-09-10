#!/usr/bin/python3
"""Fail closed unless active repositories use distribution signature trust."""

from __future__ import annotations

import os
import pathlib
import re
import shlex
import stat
import subprocess
import sys
import urllib.parse
from collections.abc import Mapping


DEBIAN_ALLOWED_HOSTS = {"deb.debian.org", "security.debian.org"}
DEBIAN_ARCHIVE_KEYRINGS = {
    "/usr/share/keyrings/debian-archive-keyring.gpg",
    "/usr/share/keyrings/debian-archive-keyring.pgp",
}
DEBIAN_GLOBAL_BYPASSES = {
    "Acquire::AllowInsecureRepositories",
    "Acquire::AllowWeakRepositories",
    "Acquire::AllowDowngradeToInsecureRepositories",
    "APT::Get::AllowUnauthenticated",
}
DEBIAN_SOURCE_BYPASSES = {
    "trusted",
    "allow-insecure",
    "allow-weak",
    "allow-downgrade-to-insecure",
}
ROCKY_REPOSITORY_KEYS = {
    repository_id: "/etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-9"
    for repository_id in ("baseos", "appstream", "extras", "crb")
}
CADDY_EPEL_REPOSITORY_KEYS = {
    repository_id: "/etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL-9"
    for repository_id in ("epel", "epel-cisco-openh264")
}
CADDY_MANAGED_MARKER = "/var/lib/homelab-reverse-proxy/managed"
CADDY_MANAGED_MARKER_CONTENT = b"managed by homelab-playbook\n"
TRUE_VALUES = {"1", "yes", "true", "on"}


def _rooted(root: pathlib.Path, target: str) -> pathlib.Path:
    path = pathlib.PurePosixPath(target)
    if path.is_absolute():
        return root / str(path).lstrip("/") if root != pathlib.Path("/") else pathlib.Path(path)
    return root / pathlib.Path(path)


def _parse_apt_config(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line.endswith(";"):
            continue
        try:
            fields = shlex.split(line[:-1])
        except ValueError as error:
            raise ValueError("APT configuration dump is malformed") from error
        if len(fields) >= 2:
            values[fields[0].casefold()] = fields[1]
    return values


def _effective_apt_get_config(config: Mapping[str, str]) -> dict[str, str]:
    """Move apt-get's binary-specific subtree into the effective root."""
    effective = dict(config)
    prefix = "binary::apt-get::"
    for key, value in config.items():
        if key.startswith(prefix):
            effective[key.removeprefix(prefix)] = value
    return effective


def _apt_path(config: Mapping[str, str], leaf: str) -> str:
    root = pathlib.PurePosixPath(config.get("dir", "/"))
    etc = pathlib.PurePosixPath(config.get("dir::etc", "etc/apt"))
    if not etc.is_absolute():
        etc = root / etc
    value = pathlib.PurePosixPath(
        config.get(leaf.casefold(), leaf.rsplit("::", 1)[-1])
    )
    if not value.is_absolute():
        value = etc / value
    return str(value)


def _require_debian_archive_key(value: str, root: pathlib.Path) -> None:
    keys = value.split()
    if len(keys) != 1 or keys[0] not in DEBIAN_ARCHIVE_KEYRINGS:
        raise ValueError("Debian source does not use the distribution archive keyring")
    if not _rooted(root, keys[0]).is_file():
        raise ValueError("Debian distribution archive keyring is absent")


def _validate_debian_uri(uri: str) -> None:
    parsed = urllib.parse.urlparse(uri)
    if parsed.scheme not in {"http", "https"} or parsed.hostname not in DEBIAN_ALLOWED_HOSTS:
        raise ValueError("enabled Debian source is not a distribution repository")


def _validate_one_line_source(line: str, root: pathlib.Path) -> int:
    try:
        fields = shlex.split(line, comments=True)
    except ValueError as error:
        raise ValueError("Debian one-line source is malformed") from error
    if not fields or fields[0] not in {"deb", "deb-src"}:
        return 0

    options: dict[str, str] = {}
    uri_index = 1
    if uri_index < len(fields) and fields[uri_index].startswith("["):
        option_fields: list[str] = []
        while uri_index < len(fields):
            field = fields[uri_index]
            option_fields.append(field)
            uri_index += 1
            if field.endswith("]"):
                break
        if not option_fields[-1].endswith("]"):
            raise ValueError("Debian source options are malformed")
        option_fields[0] = option_fields[0][1:]
        option_fields[-1] = option_fields[-1][:-1]
        for option in option_fields:
            if not option:
                continue
            key, separator, value = option.partition("=")
            if not separator:
                raise ValueError("Debian source option has no value")
            options[key.lower()] = value
    if uri_index >= len(fields):
        raise ValueError("Debian source has no URI")
    for bypass in DEBIAN_SOURCE_BYPASSES:
        if options.get(bypass, "").lower() in TRUE_VALUES:
            raise ValueError("Debian source enables an authentication bypass")
    _require_debian_archive_key(options.get("signed-by", ""), root)
    _validate_debian_uri(fields[uri_index])
    return 1


def _deb822_paragraphs(text: str) -> list[dict[str, str]]:
    paragraphs: list[dict[str, str]] = []
    for raw_paragraph in re.split(r"\n\s*\n", text):
        values: dict[str, str] = {}
        current = ""
        for raw_line in raw_paragraph.splitlines():
            if not raw_line.strip() or raw_line.lstrip().startswith("#"):
                continue
            if raw_line[:1].isspace():
                if not current:
                    raise ValueError("Debian deb822 continuation has no field")
                values[current] += " " + raw_line.strip()
                continue
            key, separator, value = raw_line.partition(":")
            if not separator:
                raise ValueError("Debian deb822 source is malformed")
            current = key.strip().lower()
            if current in values:
                raise ValueError("Debian deb822 source repeats a field")
            values[current] = value.strip()
        if values:
            paragraphs.append(values)
    return paragraphs


def _validate_deb822_source(text: str, root: pathlib.Path) -> int:
    enabled = 0
    for values in _deb822_paragraphs(text):
        if values.get("enabled", "yes").lower() in {"0", "no", "false", "off"}:
            continue
        if not set(values.get("types", "").split()) & {"deb", "deb-src"}:
            continue
        for bypass in DEBIAN_SOURCE_BYPASSES:
            if values.get(bypass, "").lower() in TRUE_VALUES:
                raise ValueError("Debian source enables an authentication bypass")
        _require_debian_archive_key(values.get("signed-by", ""), root)
        uris = values.get("uris", "").split()
        if not uris:
            raise ValueError("Debian deb822 source has no URI")
        for uri in uris:
            _validate_debian_uri(uri)
        enabled += 1
    return enabled


def validate_debian_configuration(apt_config_text: str, root: pathlib.Path = pathlib.Path("/")) -> None:
    """Validate effective APT settings and only its authoritative source paths."""
    config = _effective_apt_get_config(_parse_apt_config(apt_config_text))
    for option in DEBIAN_GLOBAL_BYPASSES:
        if config.get(option.casefold(), "").lower() in TRUE_VALUES:
            raise ValueError("effective APT configuration enables an authentication bypass")

    source_files: list[pathlib.Path] = []
    source_list = _rooted(root, _apt_path(config, "Dir::Etc::sourcelist"))
    if source_list.is_file():
        source_files.append(source_list)
    source_parts = _rooted(root, _apt_path(config, "Dir::Etc::sourceparts"))
    if source_parts.is_dir():
        source_files.extend(sorted(source_parts.glob("*.list")))
        source_files.extend(sorted(source_parts.glob("*.sources")))

    enabled = 0
    for path in source_files:
        text = path.read_text(encoding="utf-8")
        if path.suffix == ".sources":
            enabled += _validate_deb822_source(text, root)
            continue
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if line and not line.startswith("#"):
                enabled += _validate_one_line_source(line, root)
    if not enabled:
        raise ValueError("APT has no enabled distribution source")


def _path_is_in_reposdir(path: str, reposdirs: list[str], root: pathlib.Path) -> bool:
    candidate = _rooted(root, path).resolve()
    return any(candidate.is_relative_to(_rooted(root, directory).resolve()) for directory in reposdirs)


def _is_exact_caddy_marker(metadata: os.stat_result) -> bool:
    return (
        stat.S_ISREG(metadata.st_mode)
        and stat.S_IMODE(metadata.st_mode) == 0o600
        and metadata.st_uid == 0
        and metadata.st_gid == 0
        and metadata.st_nlink == 1
        and metadata.st_size == len(CADDY_MANAGED_MARKER_CONTENT)
    )


def _caddy_owns_epel(root: pathlib.Path) -> bool:
    """Accept the fixed Caddy marker without following or blocking on unsafe files."""
    marker = _rooted(root, CADDY_MANAGED_MARKER)
    try:
        descriptor = os.open(
            marker,
            os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
    except OSError:
        return False

    try:
        before = os.fstat(descriptor)
        if not _is_exact_caddy_marker(before):
            return False
        content = os.read(descriptor, len(CADDY_MANAGED_MARKER_CONTENT) + 1)
        after = os.fstat(descriptor)
        stable_fields = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_nlink",
            "st_uid",
            "st_gid",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        return (
            _is_exact_caddy_marker(after)
            and all(getattr(before, field) == getattr(after, field) for field in stable_fields)
            and content == CADDY_MANAGED_MARKER_CONTENT
        )
    except OSError:
        return False
    finally:
        os.close(descriptor)


def validate_rocky_configuration(
    effective: Mapping[str, object],
    root: pathlib.Path = pathlib.Path("/"),
) -> None:
    """Validate DNF's inherited repository objects and authoritative locations."""
    if effective.get("gpgcheck") is not True:
        raise ValueError("effective DNF package signature checking is disabled")
    if effective.get("localpkg_gpgcheck") is not True:
        raise ValueError("effective DNF local package signature checking is disabled")
    reposdirs = [str(value) for value in effective.get("reposdir", [])]
    if not reposdirs:
        raise ValueError("DNF has no effective repository directory")
    tsflags = {str(value).lower() for value in effective.get("tsflags", [])}
    if "nocrypto" in tsflags:
        raise ValueError("effective DNF configuration disables cryptographic checks")

    repositories = [
        value
        for value in effective.get("repos", [])
        if isinstance(value, Mapping) and bool(value.get("enabled"))
    ]
    if not repositories:
        raise ValueError("DNF has no enabled distribution repository")
    caddy_owns_epel = _caddy_owns_epel(root)
    for repository in repositories:
        repository_id = str(repository.get("id", ""))
        expected_key = ROCKY_REPOSITORY_KEYS.get(repository_id.lower())
        if expected_key is None and caddy_owns_epel:
            expected_key = CADDY_EPEL_REPOSITORY_KEYS.get(repository_id)
        if expected_key is None:
            raise ValueError("enabled DNF repository is not an approved repository")
        if repository.get("gpgcheck") is not True:
            raise ValueError("effective DNF repository package signature checking is disabled")
        repofile = str(repository.get("repofile", ""))
        if not repofile or not _path_is_in_reposdir(repofile, reposdirs, root):
            raise ValueError("enabled DNF repository is outside effective reposdir")
        keys = [str(value) for value in repository.get("gpgkey", [])]
        if not keys:
            raise ValueError("enabled DNF repository has no approved repository key")
        for key in keys:
            parsed = urllib.parse.urlparse(key)
            if parsed.scheme != "file" or parsed.netloc or parsed.path != expected_key:
                raise ValueError("enabled DNF repository does not use its approved key")
            if not _rooted(root, parsed.path).is_file():
                raise ValueError("configured approved repository key is absent")


def _collect_rocky_configuration() -> dict[str, object]:
    import dnf  # pylint: disable=import-outside-toplevel

    with dnf.Base() as base:
        base.conf.read()
        base.conf.debuglevel = 0
        base.conf.assumeyes = True
        base.conf.sslverify = True
        base.conf.installroot = "/"
        base.conf.substitutions.update_from_etc("/")
        if base.conf.substitutions.get("releasever") is None:
            base.conf.substitutions["releasever"] = ""
        for option in ("cachedir", "logdir", "persistdir"):
            base.conf.prepend_installroot(option)
        base.conf.clean_requirements_on_remove = False
        base.conf.install_weak_deps = True

        base.setup_loggers()
        base.init_plugins(set(), set())
        base.pre_configure_plugins()
        base.read_all_repos()
        base.configure_plugins()
        repositories = []
        for repository in base.repos.all():
            repositories.append(
                {
                    "id": str(repository.id),
                    "enabled": bool(repository.enabled),
                    "gpgcheck": bool(repository.gpgcheck),
                    "gpgkey": [str(value) for value in repository.gpgkey],
                    "repofile": str(repository.repofile),
                }
            )
        return {
            "gpgcheck": bool(base.conf.gpgcheck),
            "localpkg_gpgcheck": bool(base.conf.localpkg_gpgcheck),
            "reposdir": [str(value) for value in base.conf.reposdir],
            "tsflags": [str(value) for value in base.conf.tsflags],
            "repos": repositories,
        }


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in {"Debian", "RedHat"}:
        print("usage: validate_repository_trust.py Debian|RedHat", file=sys.stderr)
        return 2
    try:
        if sys.argv[1] == "Debian":
            apt_config = subprocess.run(
                ["/usr/bin/apt-config", "dump"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout
            validate_debian_configuration(apt_config)
        else:
            validate_rocky_configuration(_collect_rocky_configuration())
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        print(f"repository trust validation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
