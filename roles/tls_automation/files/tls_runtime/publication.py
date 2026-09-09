"""Publish validated certificate generations with durable rollback state."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat
from typing import Callable, Dict, Optional, Tuple
import uuid


_GENERATION = re.compile(r"generation-[0-9a-f]{32}\Z")
_FINGERPRINT = re.compile(r"[0-9a-f]{64}\Z")
_FILES = ("fullchain.pem", "privkey.pem")
_JOURNAL_FIELDS = {
    "version",
    "status",
    "previous",
    "previous_fingerprint",
    "generation",
    "fingerprint",
    "retired",
}
_JOURNAL_STATUSES = {
    "prepared", "switched", "rollback_pending", "rollback_failed", "restored",
    "retry_pending", "recovered",
}
_STAGING_PREFIX = "publication-stage-"
_CURRENT_PREFIX = "current-stage-"
_CANDIDATE_PREFIX = "candidate-"
_RETIRED_PREFIX = "retired-"
_PRIVATE_SUFFIX = re.compile(r"[0-9a-f]{32}\Z")


def _private_name(prefix: str, name: str) -> bool:
    return name.startswith(prefix) and bool(_PRIVATE_SUFFIX.fullmatch(name[len(prefix):]))


class PublicationError(RuntimeError):
    """Report activation and restoration failures without discarding either."""

    def __init__(
        self, activation_error: Exception, rollback_error: Optional[Exception] = None
    ):
        message = "certificate activation failed"
        if rollback_error is not None:
            message += "; rollback verification failed"
        super().__init__(message)
        self.activation_failed = True
        self.restoration_failed = rollback_error is not None
        self.activation_error = activation_error
        self.rollback_error = rollback_error


class Publisher:
    """Coordinate one fixed certificate publication root."""

    def __init__(
        self,
        root: Path,
        journal: Path,
        owner_uid: int,
        reader_gid: int,
        validate: Callable[[Path], str],
        reload_and_verify: Callable[[str], None],
        preflight: Callable[[Path], None],
        prepare=None,
    ) -> None:
        self.root = Path(root)
        self.journal = Path(journal)
        self.owner_uid = owner_uid
        self.reader_gid = reader_gid
        self.validate = validate
        self.reload_and_verify = reload_and_verify
        self.preflight = preflight
        self.prepare = prepare
        if not self.root.is_absolute() or not self.journal.is_absolute():
            raise ValueError("publication paths must be absolute")
        if self.journal == self.root or self.root in self.journal.parents:
            raise ValueError("transaction journal must be outside published root")
        if owner_uid < 0 or reader_gid < 0:
            raise ValueError("publication ownership is invalid")

    @staticmethod
    def _lstat(path: Path):
        try:
            return os.lstat(path)
        except FileNotFoundError:
            return None

    def _assert_directory(
        self,
        path: Path,
        mode: int,
        *,
        expected_gid: Optional[int] = None,
    ) -> None:
        info = self._lstat(path)
        if info is None or not stat.S_ISDIR(info.st_mode):
            raise ValueError("required TLS state directory is invalid")
        if info.st_uid != self.owner_uid:
            raise ValueError("TLS state directory owner is invalid")
        if expected_gid is not None and info.st_gid != expected_gid:
            raise ValueError("TLS state directory group is invalid")
        if stat.S_IMODE(info.st_mode) != mode:
            raise ValueError("TLS state directory mode is invalid")

    def _assert_generation(self, name: str) -> Path:
        if not isinstance(name, str) or not _GENERATION.fullmatch(name):
            raise ValueError("published generation name is invalid")
        directory = self.root / name
        self._assert_directory(directory, 0o750, expected_gid=self.reader_gid)
        entries = {entry.name for entry in directory.iterdir()}
        if entries != set(_FILES):
            raise ValueError("published generation contents are invalid")
        for filename in _FILES:
            info = self._lstat(directory / filename)
            if (
                info is None
                or not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_uid != self.owner_uid
                or info.st_gid != self.reader_gid
                or stat.S_IMODE(info.st_mode) != 0o640
            ):
                raise ValueError("published certificate file is invalid")
        return directory

    def _current_name(self) -> Optional[str]:
        current = self.root / "current"
        info = self._lstat(current)
        if info is None:
            return None
        if not stat.S_ISLNK(info.st_mode):
            raise ValueError("current certificate pointer is invalid")
        target = os.readlink(current)
        if Path(target).is_absolute() or Path(target).name != target:
            raise ValueError("current certificate pointer escapes published root")
        self._assert_generation(target)
        return target

    def _assert_journal_parent(self) -> None:
        info = self._lstat(self.journal.parent)
        if info is None or not stat.S_ISDIR(info.st_mode):
            raise ValueError("transaction directory is invalid")
        if info.st_uid != self.owner_uid or stat.S_IMODE(info.st_mode) & 0o022:
            raise ValueError("transaction directory permissions are invalid")
        root_info = self._lstat(self.root)
        if root_info is None or root_info.st_dev != info.st_dev:
            raise ValueError("TLS transaction and publication roots differ by filesystem")

    def _assert_journal_file(self) -> None:
        info = self._lstat(self.journal)
        if info is None:
            return
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != self.owner_uid
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise ValueError("transaction journal is invalid")

    def _assert_state(self) -> Optional[str]:
        self._assert_directory(
            self.root, 0o750, expected_gid=self.reader_gid
        )
        self._assert_journal_parent()
        self._assert_journal_file()
        allowed = {"current"}
        for entry in self.root.iterdir():
            if entry.name == "current":
                continue
            self._assert_generation(entry.name)
            allowed.add(entry.name)
        if {entry.name for entry in self.root.iterdir()} - allowed:
            raise ValueError("published root contains an unexpected entry")
        return self._current_name()

    def _remove_private_build(self, path: Path) -> None:
        if path.parent != self.journal.parent or not _private_name(
            _STAGING_PREFIX, path.name
        ):
            raise ValueError("publication build cleanup path is invalid")
        info = self._lstat(path)
        allowed_gids = {self._journal_parent_gid(), self.reader_gid}
        if (
            info is None
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != self.owner_uid
            or info.st_gid not in allowed_gids
            or stat.S_IMODE(info.st_mode) not in {0o700, 0o750}
        ):
            raise ValueError("publication build artifact is invalid")
        entries = {entry.name for entry in path.iterdir()}
        if not entries.issubset(set(_FILES)):
            raise ValueError("publication build contents are invalid")
        for filename in entries:
            item = path / filename
            file_info = self._lstat(item)
            if (
                file_info is None
                or not stat.S_ISREG(file_info.st_mode)
                or file_info.st_nlink != 1
                or file_info.st_uid != self.owner_uid
                or file_info.st_gid not in allowed_gids
                or stat.S_IMODE(file_info.st_mode) not in {0o600, 0o640}
            ):
                raise ValueError("publication build file is invalid")
            item.unlink()
        path.rmdir()
        self._fsync_directory(self.journal.parent)

    def _cleanup_private_artifacts(self) -> None:
        for entry in self.journal.parent.iterdir():
            if _private_name(_STAGING_PREFIX, entry.name):
                self._remove_private_build(entry)
            elif _private_name(_CURRENT_PREFIX, entry.name):
                info = self._lstat(entry)
                if (
                    info is None
                    or not stat.S_ISLNK(info.st_mode)
                    or info.st_uid != self.owner_uid
                ):
                    raise ValueError("current-pointer build artifact is invalid")
                target = os.readlink(entry)
                if Path(target).is_absolute() or not _GENERATION.fullmatch(target):
                    raise ValueError("current-pointer build target is invalid")
                entry.unlink()
                self._fsync_directory(self.journal.parent)
            elif _private_name(_CANDIDATE_PREFIX, entry.name):
                self._remove_snapshot(entry)
            elif _private_name(_RETIRED_PREFIX, entry.name):
                self._remove_retired(entry)
            elif _private_name("." + self.journal.name + ".", entry.name):
                info = self._lstat(entry)
                allowed_gids = {self._journal_parent_gid(), self.reader_gid}
                if (
                    info is None
                    or not stat.S_ISREG(info.st_mode)
                    or info.st_nlink != 1
                    or info.st_uid != self.owner_uid
                    or info.st_gid not in allowed_gids
                    or stat.S_IMODE(info.st_mode) != 0o600
                ):
                    raise ValueError("journal build artifact is invalid")
                entry.unlink()
                self._fsync_directory(self.journal.parent)

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _journal_parent_gid(self) -> int:
        return os.lstat(self.journal.parent).st_gid

    def _write_owned_file(self, path: Path, contents: bytes, mode: int) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags, mode)
        try:
            os.fchown(descriptor, self.owner_uid, self.reader_gid)
            os.fchmod(descriptor, mode)
            with os.fdopen(descriptor, "wb", closefd=False) as output:
                output.write(contents)
                output.flush()
                os.fsync(output.fileno())
        finally:
            os.close(descriptor)

    def _snapshot(self, fullchain: bytes, private_key: bytes) -> Path:
        directory = self.journal.parent / (_CANDIDATE_PREFIX + uuid.uuid4().hex)
        directory.mkdir(mode=0o700)
        try:
            os.chown(directory, self.owner_uid, self.reader_gid)
            directory.chmod(0o700)
            self._write_owned_file(directory / _FILES[0], fullchain, 0o600)
            self._write_owned_file(directory / _FILES[1], private_key, 0o600)
            self._fsync_directory(directory)
        except BaseException:
            self._remove_snapshot(directory)
            raise
        return directory

    def _remove_snapshot(self, directory: Path) -> None:
        if directory.parent != self.journal.parent or not _private_name(
            _CANDIDATE_PREFIX, directory.name
        ):
            raise ValueError("candidate cleanup path is invalid")
        info = self._lstat(directory)
        if info is None:
            return
        allowed_gids = {self._journal_parent_gid(), self.reader_gid}
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != self.owner_uid
            or info.st_gid not in allowed_gids
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise ValueError("candidate cleanup directory is invalid")
        entries = {entry.name for entry in directory.iterdir()}
        if not entries.issubset(set(_FILES)):
            raise ValueError("candidate cleanup contents are invalid")
        for filename in entries:
            path = directory / filename
            file_info = self._lstat(path)
            if (
                file_info is None
                or not stat.S_ISREG(file_info.st_mode)
                or file_info.st_nlink != 1
                or file_info.st_uid != self.owner_uid
                or file_info.st_gid not in allowed_gids
                or stat.S_IMODE(file_info.st_mode) != 0o600
            ):
                raise ValueError("candidate cleanup file is invalid")
            path.unlink()
        directory.rmdir()
        self._fsync_directory(self.journal.parent)

    def _remove_retired(self, directory: Path) -> None:
        """Remove only a failed generation atomically retired from publication."""
        if directory.parent != self.journal.parent or not _private_name(
            _RETIRED_PREFIX, directory.name
        ):
            raise ValueError("retired cleanup path is invalid")
        info = self._lstat(directory)
        if info is None:
            return
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != self.owner_uid
            or info.st_gid != self.reader_gid
            or stat.S_IMODE(info.st_mode) != 0o750
        ):
            raise ValueError("retired generation is invalid")
        entries = {entry.name for entry in directory.iterdir()}
        if not entries.issubset(set(_FILES)):
            raise ValueError("retired generation contents are invalid")
        for filename in entries:
            path = directory / filename
            file_info = self._lstat(path)
            if (
                file_info is None
                or not stat.S_ISREG(file_info.st_mode)
                or file_info.st_nlink != 1
                or file_info.st_uid != self.owner_uid
                or file_info.st_gid != self.reader_gid
                or stat.S_IMODE(file_info.st_mode) != 0o640
            ):
                raise ValueError("retired certificate file is invalid")
            path.unlink()
        directory.rmdir()
        self._fsync_directory(self.journal.parent)

    @staticmethod
    def _validated_fingerprint(value: str) -> str:
        if not isinstance(value, str) or not _FINGERPRINT.fullmatch(value):
            raise ValueError("certificate validator returned an invalid fingerprint")
        return value

    def _create_generation(
        self, fullchain: bytes, private_key: bytes
    ) -> Tuple[str, Path]:
        name = "generation-" + uuid.uuid4().hex
        directory = self.root / name
        staging = self.journal.parent / (_STAGING_PREFIX + uuid.uuid4().hex)
        staging.mkdir(mode=0o700)
        try:
            os.chown(staging, self.owner_uid, self.reader_gid)
            staging.chmod(0o750)
            self._write_owned_file(staging / _FILES[0], fullchain, 0o640)
            self._write_owned_file(staging / _FILES[1], private_key, 0o640)
            self._fsync_directory(staging)
            os.replace(staging, directory)
            self._fsync_directory(self.root)
            self._fsync_directory(self.journal.parent)
        except BaseException:
            if self._lstat(staging) is not None:
                self._remove_private_build(staging)
            raise
        return name, directory

    def _retire_unjournaled_generation(self, name: str) -> None:
        source = self._assert_generation(name)
        retired = self.journal.parent / (_RETIRED_PREFIX + uuid.uuid4().hex)
        os.replace(source, retired)
        self._fsync_directory(self.root)
        self._fsync_directory(self.journal.parent)
        self._remove_retired(retired)

    def _write_journal(self, record: Dict[str, object]) -> None:
        temporary = self.journal.with_name(
            "." + self.journal.name + "." + uuid.uuid4().hex
        )
        encoded = (json.dumps(record, sort_keys=True) + "\n").encode("utf-8")
        try:
            self._write_owned_file(temporary, encoded, 0o600)
            os.replace(temporary, self.journal)
            self._fsync_directory(self.journal.parent)
        finally:
            if self._lstat(temporary) is not None:
                temporary.unlink()

    def _remove_journal(self) -> None:
        self._assert_journal_file()
        if self._lstat(self.journal) is not None:
            self.journal.unlink()
            self._fsync_directory(self.journal.parent)

    def _switch_current(self, generation: Optional[str]) -> None:
        current = self.root / "current"
        if generation is None:
            info = self._lstat(current)
            if info is not None:
                if not stat.S_ISLNK(info.st_mode):
                    raise ValueError("current certificate pointer is invalid")
                current.unlink()
                self._fsync_directory(self.root)
            return
        self._assert_generation(generation)
        temporary = self.journal.parent / (_CURRENT_PREFIX + uuid.uuid4().hex)
        os.symlink(generation, temporary)
        os.lchown(temporary, self.owner_uid, self.reader_gid)
        try:
            os.replace(temporary, current)
            self._fsync_directory(self.root)
            self._fsync_directory(self.journal.parent)
        finally:
            if self._lstat(temporary) is not None:
                temporary.unlink()

    def _journal_record(
        self,
        status: str,
        previous: Optional[str],
        previous_fingerprint: Optional[str],
        generation: str,
        fingerprint: str,
    ) -> Dict[str, object]:
        return {
            "version": 1,
            "status": status,
            "previous": previous,
            "previous_fingerprint": previous_fingerprint,
            "generation": generation,
            "fingerprint": fingerprint,
            "retired": None,
        }

    def _finish_restored_cleanup(self, record: Dict[str, object]) -> None:
        """Make restoration terminal before destructively cleaning its candidate."""
        generation = str(record["generation"])
        retired = record.get("retired")
        if retired is None:
            retired = _RETIRED_PREFIX + uuid.uuid4().hex
            record["retired"] = retired
            record["status"] = "restored"
            self._write_journal(record)
        if not isinstance(retired, str) or not _private_name(_RETIRED_PREFIX, retired):
            raise ValueError("transaction retired generation is invalid")
        source = self.root / generation
        destination = self.journal.parent / retired
        if self._lstat(source) is not None:
            self._assert_generation(generation)
            if self._lstat(destination) is not None:
                raise ValueError("retired generation destination already exists")
            os.replace(source, destination)
            self._fsync_directory(self.root)
            self._fsync_directory(self.journal.parent)
        elif self._lstat(destination) is None:
            raise ValueError("restored transaction generation is missing")
        self._remove_journal()
        self._remove_retired(destination)

    def _refresh_binding(self, record):
        if "caddy" in record and self._lstat(self.journal) is not None:
            latest = self._read_journal()
            if latest["generation"] != record["generation"]:
                raise ValueError("publication identity changed during callback")
            for key in ("restart", "disk_recovery"):
                record["caddy"][key] = latest["caddy"][key]

    def _rollback(
        self,
        record: Dict[str, object],
        activation_error: Exception,
    ) -> None:
        self._refresh_binding(record)
        previous = record["previous"]
        previous_fingerprint = record["previous_fingerprint"]
        if "caddy" in record:
            record["caddy"]["activation_failed"] = True
        try:
            self._switch_current(previous if isinstance(previous, str) else None)
            record["status"] = "rollback_pending"
            self._write_journal(record)
            self.reload_and_verify(
                previous_fingerprint if isinstance(previous_fingerprint, str) else ""
            )
        except Exception as rollback_error:
            self._refresh_binding(record)
            record["status"] = "rollback_failed"
            if "caddy" in record:
                record["caddy"]["restoration_failed"] = True
            self._write_journal(record)
            raise PublicationError(activation_error, rollback_error) from rollback_error
        self._refresh_binding(record)
        self._finish_restored_cleanup(record)
        raise PublicationError(activation_error)

    def publish(self, fullchain: bytes, private_key: bytes) -> bool:
        """Publish a generation, returning false when its fingerprint is active.

        An empty fingerprint passed to ``reload_and_verify`` means that no
        ``current`` generation exists. The callback must deactivate the fixed
        route and verify that it no longer serves the rejected certificate.
        """

        if not isinstance(fullchain, bytes) or not isinstance(private_key, bytes):
            raise ValueError("publication material must be bytes")
        if self._lstat(self.journal) is not None:
            raise RuntimeError("an incomplete TLS publication requires recovery")
        previous = self._assert_state()
        self._cleanup_private_artifacts()
        previous_fingerprint = None
        previous_material = None
        if previous is not None:
            previous_path = self.root / previous
            previous_fingerprint = self._validated_fingerprint(
                self.validate(previous_path)
            )
            previous_material = tuple(
                (previous_path / filename).read_bytes() for filename in _FILES
            )

        snapshot = self._snapshot(fullchain, private_key)
        try:
            fingerprint = self._validated_fingerprint(self.validate(snapshot))
            if (
                fingerprint == previous_fingerprint
                and previous_material == (fullchain, private_key)
            ):
                self.reload_and_verify(fingerprint)
                return False
            if self._assert_state() != previous:
                raise RuntimeError("active certificate changed during publication")
            generation, generation_path = self._create_generation(
                fullchain, private_key
            )
            try:
                self.preflight(generation_path)
                if self._assert_state() != previous:
                    raise RuntimeError("active certificate changed during preflight")
            except Exception:
                self._retire_unjournaled_generation(generation)
                raise
            record = self._journal_record(
                "prepared",
                previous,
                previous_fingerprint,
                generation,
                fingerprint,
            )
            if self.prepare is not None:
                try:
                    record["caddy"] = self.prepare(record)
                    self._validate_binding(record["caddy"])
                except Exception:
                    self._retire_unjournaled_generation(generation)
                    raise
            self._write_journal(record)
            try:
                self._switch_current(generation)
                record["status"] = "switched"
                self._write_journal(record)
                self.reload_and_verify(fingerprint)
            except Exception as activation_error:
                if self._current_name() == generation:
                    self._rollback(record, activation_error)
                else:
                    self._remove_journal()
                    self._retire_unjournaled_generation(generation)
                    raise PublicationError(activation_error)
            self._remove_journal()
            return True
        finally:
            self._remove_snapshot(snapshot)

    def _read_journal(self) -> Dict[str, object]:
        self._assert_journal_file()
        try:
            record = json.loads(self.journal.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise ValueError("transaction journal is malformed") from error
        if not isinstance(record, dict) or set(record) not in (_JOURNAL_FIELDS, _JOURNAL_FIELDS | {"caddy"}):
            raise ValueError("transaction journal schema is invalid")
        if record.get("version") != 1 or record.get("status") not in _JOURNAL_STATUSES:
            raise ValueError("transaction journal state is invalid")
        generation = record.get("generation")
        fingerprint = record.get("fingerprint")
        previous = record.get("previous")
        previous_fingerprint = record.get("previous_fingerprint")
        retired = record.get("retired")
        if not isinstance(generation, str) or not _GENERATION.fullmatch(generation):
            raise ValueError("transaction generation is invalid")
        self._validated_fingerprint(fingerprint)  # type: ignore[arg-type]
        if (previous is None) != (previous_fingerprint is None):
            raise ValueError("transaction previous generation is invalid")
        if previous is not None:
            if not isinstance(previous, str) or not _GENERATION.fullmatch(previous):
                raise ValueError("transaction previous generation is invalid")
            self._validated_fingerprint(previous_fingerprint)  # type: ignore[arg-type]
        if retired is not None and (
            not isinstance(retired, str)
            or not _private_name(_RETIRED_PREFIX, retired)
        ):
            raise ValueError("transaction retired generation is invalid")
        if (record["status"] == "restored") != (retired is not None):
            raise ValueError("transaction terminal state is invalid")
        if "caddy" in record:
            self._validate_binding(record["caddy"])
        return record

    @staticmethod
    def _validate_binding(binding):
        fields = {"desired_revision", "previous_boot", "candidate_boot", "disk_recovery",
                  "restart", "activation_failed", "restoration_failed"}
        if (not isinstance(binding, dict) or set(binding) != fields
                or not isinstance(binding["desired_revision"], str)
                or not _FINGERPRINT.fullmatch(binding["desired_revision"])
                or binding["disk_recovery"] not in (None, "pending", "restored")
                or any(type(binding[name]) is not bool for name in
                       ("restart", "activation_failed", "restoration_failed"))
                or any(not isinstance(binding[name], str) or len(binding[name].encode()) > 1048576
                       for name in ("previous_boot", "candidate_boot"))):
            raise ValueError("invalid Caddy publication binding")

    def _retry_retained(self, record: Dict[str, object]) -> Dict[str, object]:
        """Retry retained bytes after failed restoration, without new issuance.

        Both prior failures remain encoded by retry_pending/recovered. The same
        transition can resume on either side of the atomic pointer replacement.
        Unusable candidates leave the journal intact and block reconciliation.
        """
        generation = str(record["generation"])
        current = self._assert_state()
        if current not in (record["previous"], generation):
            raise ValueError("active generation does not match recovery journal")
        path = self._assert_generation(generation)
        actual = self._validated_fingerprint(self.validate(path))
        if actual != record["fingerprint"]:
            raise ValueError("journal fingerprint does not match retained generation")
        # Runtime preflight checks exact SAN, current public trust and minimum
        # remaining lifetime, then validates the adapter's candidate access.
        self.preflight(path)
        if self._assert_state() != current:
            raise RuntimeError("active certificate changed during recovery preflight")
        record["status"] = "retry_pending"
        self._write_journal(record)
        try:
            self._switch_current(generation)
            self.reload_and_verify(actual)
        except Exception as activation_error:
            self._rollback(record, activation_error)
        self._refresh_binding(record)
        record["status"] = "recovered"
        self._write_journal(record)
        self._remove_journal()
        binding = record.get("caddy", {})
        return {"publication": "changed", "activation_failed": binding.get("activation_failed", True),
                "restoration_failed": binding.get("restoration_failed", True)}

    def recover(self) -> Optional[Dict[str, object]]:
        """Finish or roll back the one journaled publication transaction."""

        current = self._assert_state()
        if self._lstat(self.journal) is None:
            self._cleanup_private_artifacts()
            return
        record = self._read_journal()
        generation = str(record["generation"])
        previous = record["previous"]

        if record["status"] == "restored":
            self._finish_restored_cleanup(record)
            return

        self._assert_generation(generation)
        if previous is not None:
            self._assert_generation(str(previous))

        if (record["status"] in {"retry_pending", "recovered"}
                or record.get("caddy", {}).get("disk_recovery") is not None):
            try:
                return self._retry_retained(record)
            except Exception as error:
                raise PublicationError(
                    RuntimeError("prior certificate activation failed"), error
                ) from error

        if current == generation:
            actual = self._validated_fingerprint(self.validate(self.root / generation))
            if actual != record["fingerprint"]:
                raise ValueError("journal fingerprint does not match generation")
            try:
                self.preflight(self.root / generation)
                self.reload_and_verify(actual)
            except Exception as activation_error:
                self._rollback(record, activation_error)
                raise
            self._remove_journal()
            return

        expected_previous = previous if isinstance(previous, str) else None
        if current != expected_previous:
            raise ValueError("active generation does not match transaction journal")
        if record["status"] == "prepared" and expected_previous is None:
            self._finish_restored_cleanup(record)
            return
        expected_fingerprint = record["previous_fingerprint"]
        if expected_previous is not None:
            actual = self._validated_fingerprint(
                self.validate(self.root / expected_previous)
            )
            if actual != expected_fingerprint:
                raise ValueError("journal fingerprint does not match previous generation")
        try:
            self.reload_and_verify(
                expected_fingerprint if isinstance(expected_fingerprint, str) else ""
            )
        except Exception as rollback_error:
            self._refresh_binding(record)
            record["status"] = "rollback_failed"
            if "caddy" in record:
                record["caddy"]["restoration_failed"] = True
            self._write_journal(record)
            try:
                return self._retry_retained(record)
            except Exception as candidate_error:
                # Neither a failed restoration nor invalid pending bytes permit
                # a fresh order. Keep durable state for the next bounded retry.
                raise PublicationError(
                    RuntimeError("prior certificate activation failed"), rollback_error
                ) from candidate_error
        activation_error = RuntimeError("prior certificate activation failed")
        was_prepared = record["status"] == "prepared"
        self._finish_restored_cleanup(record)
        if was_prepared:
            return None
        raise PublicationError(activation_error)
