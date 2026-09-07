"""Validate encrypted inventory structure, never decrypt or quote its contents."""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

REQUIRED_SOURCES = (
    "inventory/production/group_vars/os_managed/secrets.sops.yml",
    "inventory/staging/group_vars/semaphore/secrets.sops.yml",
    "inventory/frozen/k3s/group_vars/k3s_cluster/secrets.sops.yml",
)
INVENTORY_PATTERN = r"^inventory/(production|staging|frozen/k3s)/(group_vars|host_vars)/.*\.sops\.yml$"
RECIPIENT = re.compile(r"age1[023456789acdefghjklmnpqrstuvwxyz]{58}")
ENCRYPTED = re.compile(
    r"ENC\[AES256_GCM,data:[A-Za-z0-9+/]*={0,2},"
    r"iv:[A-Za-z0-9+/]+={0,2},tag:[A-Za-z0-9+/]+={0,2},"
    r"type:(?:str|int|float|bool|bytes|comment)\]"
)


class UniqueLoader(yaml.SafeLoader):
    """Do not let duplicate YAML keys conceal plaintext from validation."""


def unique_mapping(loader, node):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node)
        if not isinstance(key, str) or key in result:
            raise ValueError("invalid mapping")
        result[key] = loader.construct_object(value_node)
    return result


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)


def regular_file(path: Path) -> bool:
    return not any(part.is_symlink() for part in (path, *path.parents)) and path.is_file()


def read_yaml(path: Path):
    if not regular_file(path):
        raise ValueError("not a regular file")
    return yaml.load(path.read_bytes(), Loader=UniqueLoader)


def encrypted_values(value, seen=None) -> bool:
    # SOPS preserves null and empty strings/containers. Reject aliases with cycles.
    if value is None or value == "":
        return True
    if isinstance(value, str):
        return bool(ENCRYPTED.fullmatch(value))
    if not isinstance(value, (dict, list)):
        return False
    seen = set() if seen is None else seen
    if id(value) in seen:
        return False
    seen.add(id(value))
    children = value.values() if isinstance(value, dict) else value
    result = all(encrypted_values(child, seen) for child in children)
    seen.remove(id(value))
    return result


def validate_encrypted_file(path: Path, recipients: set[str]) -> list[str]:
    # All errors are fixed text. YAML parser diagnostics can contain plaintext.
    try:
        document = read_yaml(path)
        if not isinstance(document, dict) or not document or "sops" not in document:
            raise ValueError()
        metadata = document["sops"]
        if not isinstance(metadata, dict) or not ENCRYPTED.fullmatch(metadata.get("mac", "")):
            raise ValueError()
        if metadata.get("encrypted_regex") != "^(.*)$":
            raise ValueError()
        if any(metadata.get(name) for name in (
            "kms", "gcp_kms", "azure_kv", "hc_vault", "pgp", "key_groups",
            "unencrypted_suffix", "unencrypted_regex", "encrypted_suffix",
            "unencrypted_comment_regex", "encrypted_comment_regex",
        )):
            raise ValueError()
        age = metadata.get("age")
        if not isinstance(age, list) or not age or not recipients:
            raise ValueError()
        actual = []
        for entry in age:
            recipient = entry["recipient"]
            wrapped = entry["enc"]
            if not RECIPIENT.fullmatch(recipient) or not isinstance(wrapped, str):
                raise ValueError()
            if not (wrapped.startswith("-----BEGIN AGE ENCRYPTED FILE-----\n")
                    and wrapped.rstrip().endswith("-----END AGE ENCRYPTED FILE-----")):
                raise ValueError()
            actual.append(recipient)
        if set(actual) != recipients or len(actual) != len(set(actual)):
            raise ValueError()
        values = {key: value for key, value in document.items() if key != "sops"}
        if not values or not encrypted_values(values):
            raise ValueError()
    except (OSError, ValueError, TypeError, KeyError, yaml.YAMLError, RecursionError):
        return ["invalid encrypted structure or recipients (contents suppressed)"]
    return []


def policy_recipients(root: Path) -> set[str]:
    policy = read_yaml(root / ".sops.yaml")
    rules = policy["creation_rules"]
    # One current access scope; future scoped controller access changes this contract.
    if len(rules) != 1 or set(rules[0]) != {"path_regex", "age", "encrypted_regex"}:
        raise ValueError()
    rule = rules[0]
    if rule["path_regex"] != INVENTORY_PATTERN or rule["encrypted_regex"] != "^(.*)$":
        raise ValueError()
    if not isinstance(rule["age"], str):
        raise ValueError()
    recipients = [value.strip() for value in rule["age"].split(",")]
    if not recipients or any(not RECIPIENT.fullmatch(value) for value in recipients):
        raise ValueError()
    if len(recipients) != len(set(recipients)):
        raise ValueError()
    return set(recipients)


def validate_repository(root: Path) -> list[str]:
    errors = []
    try:
        recipients = policy_recipients(root)
    except (OSError, ValueError, KeyError, TypeError, yaml.YAMLError, RecursionError):
        recipients = set()
        errors.append(".sops.yaml: configure valid dedicated public age recipients before cutover")
    sources = set(REQUIRED_SOURCES)
    # Discover only filenames; protected contents are read only by the safe parser.
    sources.update(path.relative_to(root).as_posix() for path in (root / "inventory").rglob("*.sops.yml"))
    for name in sorted(sources):
        path = root / name
        if not regular_file(path):
            errors.append(f"{name}: missing or non-regular encrypted source; operator cutover required")
            continue
        errors.extend(f"{name}: {error}" for error in validate_encrypted_file(path, recipients))
    return errors


def main():
    errors = validate_repository(Path(__file__).resolve().parents[2])
    for error in errors:
        print(error, file=sys.stderr)
    if not errors:
        print("Encrypted inventory structure and recipients are valid (no decryption).")
    return bool(errors)


if __name__ == "__main__":
    raise SystemExit(main())
