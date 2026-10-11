"""Health and telemetry status endpoints."""

from typing import Any

from fastapi import APIRouter, Depends, Request

from hids.db.database import DatabaseManager

router = APIRouter(prefix="/health", tags=["Health"])


def get_db(request: Request) -> DatabaseManager:
    """Dependency retrieving database manager from app state."""
    db: DatabaseManager = request.app.state.db
    return db


@router.get("", response_model=dict[str, Any])
async def health_check(db: DatabaseManager = Depends(get_db)) -> dict[str, Any]:
    """Retrieve service health and status metrics."""
    # Verify database connection
    events = db.list_events(limit=1)
    return {
        "status": "healthy",
        "service": "host-intrusion-detection-system",
        "database_connected": True,
        "sample_event_queried": len(events) >= 0,
    }
