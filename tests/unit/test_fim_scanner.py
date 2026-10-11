"""Unit tests for File Integrity Monitoring (FIM) collector."""

from pathlib import Path

from hids.collectors.fim import FileIntegrityScanner
from hids.models.enums import EventCategory, FIMAction


def test_fim_scan_file_and_hash(tmp_path: Path) -> None:
    test_file = tmp_path / "important.conf"
    test_file.write_text("root_allowed=true\n")

    scanner = FileIntegrityScanner()
    rec = scanner.scan_file(test_file)

    assert rec is not None
    assert rec.file_path == test_file.resolve()
    assert rec.size_bytes > 0
    assert len(rec.sha256_hash) == 64
    assert not rec.is_directory


def test_fim_ignore_patterns(tmp_path: Path) -> None:
    scanner = FileIntegrityScanner(ignore_patterns=["*.swp", "temp_*"])

    assert scanner.is_ignored(tmp_path / "test.swp")
    assert scanner.is_ignored(tmp_path / "temp_file.txt")
    assert not scanner.is_ignored(tmp_path / "critical.py")


def test_fim_compare_baselines_created_modified_deleted(tmp_path: Path) -> None:
    f1 = tmp_path / "file1.txt"
    f2 = tmp_path / "file2.txt"

    f1.write_text("version 1")
    f2.write_text("constant")

    scanner = FileIntegrityScanner()
    baseline1 = scanner.scan_directory(tmp_path)

    # 1. Modify f1
    f1.write_text("version 2 (modified)")
    # 2. Delete f2
    f2.unlink()
    # 3. Create f3
    f3 = tmp_path / "file3.txt"
    f3.write_text("newly created")

    baseline2 = scanner.scan_directory(tmp_path)
    diffs = scanner.compare_baselines(baseline1, baseline2)

    diff_map = {d.file_path.name: d for d in diffs}

    assert "file1.txt" in diff_map
    assert diff_map["file1.txt"].action == FIMAction.MODIFIED
    assert any("SHA-256 hash changed" in r for r in diff_map["file1.txt"].change_reasons)

    assert "file2.txt" in diff_map
    assert diff_map["file2.txt"].action == FIMAction.DELETED

    assert "file3.txt" in diff_map
    assert diff_map["file3.txt"].action == FIMAction.CREATED

    # Test event conversion
    event = scanner.create_host_event(diff_map["file1.txt"])
    assert event.category == EventCategory.FILE_INTEGRITY
    assert event.action == FIMAction.MODIFIED.value
