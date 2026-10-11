"""File Integrity Monitoring status endpoints."""

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from hids.db.database import DatabaseManager

router = APIRouter(prefix="/fim", tags=["File Integrity Monitoring"])


def get_db(request: Request) -> DatabaseManager:
    """Dependency retrieving database manager from app state."""
    db: DatabaseManager = request.app.state.db
    return db


@router.get("/baselines", response_model=list[dict[str, Any]])
async def list_baselines(
    limit: int = Query(default=100, ge=1, le=1000),
    db: DatabaseManager = Depends(get_db),
) -> list[dict[str, Any]]:
    """List recorded baseline file records."""
    baselines = db.load_fim_baseline()
    records = list(baselines.values())[:limit]
    return [r.model_dump(mode="json") for r in records]


@router.get("/baselines/{path:path}", response_model=dict[str, Any])
async def get_baseline(
    path: str,
    db: DatabaseManager = Depends(get_db),
) -> dict[str, Any]:
    """Retrieve baseline record for a specific file path."""
    clean_path = f"/{path}" if not path.startswith("/") else path
    baselines = db.load_fim_baseline()
    record = baselines.get(clean_path)
    if not record:
        raise HTTPException(
            status_code=404,
            detail=f"Baseline record for path '{clean_path}' not found",
        )
    return record.model_dump(mode="json")
