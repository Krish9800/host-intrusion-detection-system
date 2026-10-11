"""Host telemetry events endpoints."""

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from hids.db.database import DatabaseManager
from hids.models.enums import EventCategory

router = APIRouter(prefix="/events", tags=["Events"])


def get_db(request: Request) -> DatabaseManager:
    """Dependency retrieving database manager from app state."""
    db: DatabaseManager = request.app.state.db
    return db


@router.get("", response_model=list[dict[str, Any]])
async def list_events(
    category: str | None = Query(
        default=None,
        description="Filter by event category: FILE_INTEGRITY, PROCESS_ACTIVITY, AUTHENTICATION",
    ),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    db: DatabaseManager = Depends(get_db),
) -> list[dict[str, Any]]:
    """List ingested host telemetry events with optional category filtering."""
    events = db.list_events(limit=limit, offset=offset)
    if category:
        try:
            category_enum = EventCategory(category.upper())
            events = [e for e in events if e.category == category_enum]
        except ValueError:
            valid_cats = [c.value for c in EventCategory]
            raise HTTPException(
                status_code=400,
                detail=f"Invalid category '{category}'. Valid values: {valid_cats}",
            ) from None

    return [event.model_dump(mode="json") for event in events]
