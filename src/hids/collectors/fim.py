"""Cryptographic File Integrity Monitoring (FIM) scanner and change detector."""

import fnmatch
import hashlib
import os
import stat
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, Field

from hids.models.enums import EventCategory, FIMAction
from hids.models.telemetry import FileIntegrityRecord, HostEvent


class FIMChangeDiff(BaseModel):
    """Detected difference between two file integrity states."""

    file_path: Path
    action: FIMAction
    previous_record: FileIntegrityRecord | None = None
    current_record: FileIntegrityRecord | None = None
    change_reasons: list[str] = Field(default_factory=list)


class FileIntegrityScanner:
    """Computes SHA-256 baselines and diffs file system modifications."""

    def __init__(self, ignore_patterns: list[str] | None = None) -> None:
        self.ignore_patterns = ignore_patterns or []

    def is_ignored(self, path: Path) -> bool:
        """Check if path matches configured exclusion wildcards."""
        path_str = str(path)
        for pattern in self.ignore_patterns:
            if fnmatch.fnmatch(path_str, pattern) or fnmatch.fnmatch(path.name, pattern):
                return True
        return False

    @staticmethod
    def calculate_sha256(path: Path) -> str:
        """Stream compute SHA-256 cryptographic digest of a file."""
        if not path.is_file():
            return "0" * 64

        hasher = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                while chunk := f.read(65536):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except (PermissionError, FileNotFoundError, OSError):
            return "0" * 64

    def scan_file(self, path: Path) -> FileIntegrityRecord | None:
        """Inspect file attributes and calculate checksum."""
        if self.is_ignored(path):
            return None

        try:
            st = path.stat()
            is_dir = stat.S_ISDIR(st.st_mode)
            file_hash = "DIRECTORY" if is_dir else self.calculate_sha256(path)
            mode_str = stat.filemode(st.st_mode)

            return FileIntegrityRecord(
                file_path=path.resolve(),
                sha256_hash=file_hash,
                size_bytes=st.st_size,
                mode_permissions=mode_str,
                owner_uid=st.st_uid,
                group_gid=st.st_gid,
                modified_time=datetime.fromtimestamp(st.st_mtime, tz=UTC),
                is_directory=is_dir,
            )
        except (FileNotFoundError, PermissionError, OSError):
            return None

    def scan_directory(
        self,
        directory: Path,
        recursive: bool = True,
    ) -> dict[str, FileIntegrityRecord]:
        """Scan directory and return mapping of path strings to integrity records."""
        baseline: dict[str, FileIntegrityRecord] = {}
        if not directory.exists():
            return baseline

        if recursive:
            for root, dirs, files in os.walk(directory):
                # Filter out ignored directories
                dirs[:] = [d for d in dirs if not self.is_ignored(Path(root) / d)]
                for fname in files:
                    fpath = Path(root) / fname
                    rec = self.scan_file(fpath)
                    if rec:
                        baseline[str(rec.file_path)] = rec
        else:
            for item in directory.iterdir():
                if item.is_file():
                    rec = self.scan_file(item)
                    if rec:
                        baseline[str(rec.file_path)] = rec

        return baseline

    def compare_baselines(
        self,
        old_baseline: dict[str, FileIntegrityRecord],
        new_baseline: dict[str, FileIntegrityRecord],
    ) -> list[FIMChangeDiff]:
        """Compute delta changes between previous and newly scanned baseline."""
        diffs: list[FIMChangeDiff] = []

        all_keys = set(old_baseline.keys()) | set(new_baseline.keys())

        for key in sorted(all_keys):
            old_rec = old_baseline.get(key)
            new_rec = new_baseline.get(key)

            if old_rec is None and new_rec is not None:
                # Newly created file
                diffs.append(
                    FIMChangeDiff(
                        file_path=new_rec.file_path,
                        action=FIMAction.CREATED,
                        current_record=new_rec,
                        change_reasons=["File created on host"],
                    )
                )
            elif old_rec is not None and new_rec is None:
                # Deleted file
                diffs.append(
                    FIMChangeDiff(
                        file_path=old_rec.file_path,
                        action=FIMAction.DELETED,
                        previous_record=old_rec,
                        change_reasons=["File deleted from host"],
                    )
                )
            elif old_rec is not None and new_rec is not None:
                reasons: list[str] = []
                # Check hash modification
                if old_rec.sha256_hash != new_rec.sha256_hash:
                    reasons.append(
                        f"SHA-256 hash changed: {old_rec.sha256_hash[:8]} -> "
                        f"{new_rec.sha256_hash[:8]}"
                    )
                # Check size change
                if old_rec.size_bytes != new_rec.size_bytes:
                    reasons.append(
                        f"Size changed from {old_rec.size_bytes}B to {new_rec.size_bytes}B"
                    )
                # Check permission mode modification
                if old_rec.mode_permissions != new_rec.mode_permissions:
                    reasons.append(
                        f"Permissions changed from {old_rec.mode_permissions} to "
                        f"{new_rec.mode_permissions}"
                    )

                # Check owner/group modification
                if old_rec.owner_uid != new_rec.owner_uid or old_rec.group_gid != new_rec.group_gid:
                    reasons.append(
                        f"Ownership changed from {old_rec.owner_uid}:{old_rec.group_gid} to "
                        f"{new_rec.owner_uid}:{new_rec.group_gid}"
                    )

                if reasons:
                    act = (
                        FIMAction.PERMISSION_CHANGED
                        if (
                            old_rec.sha256_hash == new_rec.sha256_hash
                            and old_rec.mode_permissions != new_rec.mode_permissions
                        )
                        else FIMAction.MODIFIED
                    )
                    diffs.append(
                        FIMChangeDiff(
                            file_path=new_rec.file_path,
                            action=act,
                            previous_record=old_rec,
                            current_record=new_rec,
                            change_reasons=reasons,
                        )
                    )

        return diffs

    def create_host_event(self, diff: FIMChangeDiff) -> HostEvent:
        """Convert a FIM change diff into a unified HostEvent."""
        return HostEvent(
            category=EventCategory.FILE_INTEGRITY,
            action=diff.action.value,
            source_component="fim_scanner",
            fim_record=diff.current_record or diff.previous_record,
            details={
                "file_path": str(diff.file_path),
                "reasons": diff.change_reasons,
                "action": diff.action.value,
            },
        )
