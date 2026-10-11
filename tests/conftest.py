"""Shared test fixtures for HIDS testing."""

from pathlib import Path

import pytest

from hids.config.settings import Settings


@pytest.fixture
def temp_settings(tmp_path: Path) -> Settings:
    """Provide isolated settings with temporary storage directory."""
    db_path = tmp_path / "test_hids.db"
    return Settings(
        agent_id="test-hids-agent",
        environment="test",
        db_path=db_path,
        fim_paths_to_watch=[tmp_path / "watched"],
    )
