"""Alert inspection and triage endpoints."""

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from hids.db.database import DatabaseManager
from hids.models.enums import Severity

router = APIRouter(prefix="/alerts", tags=["Alerts"])


def get_db(request: Request) -> DatabaseManager:
    """Dependency retrieving database manager from app state."""
    db: DatabaseManager = request.app.state.db
    return db


@router.get("", response_model=list[dict[str, Any]])
async def list_alerts(
    severity: str | None = Query(
        default=None, description="Filter by severity: informational, low, medium, high, critical"
    ),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    db: DatabaseManager = Depends(get_db),
) -> list[dict[str, Any]]:
    """List intrusion alerts with optional severity filtering."""
    severity_enum = None
    if severity:
        try:
            severity_enum = Severity(severity.upper())
        except ValueError:
            valid_vals = [s.value for s in Severity]
            raise HTTPException(
                status_code=400,
                detail=f"Invalid severity '{severity}'. Valid values: {valid_vals}",
            ) from None

    alerts = db.list_alerts(severity=severity_enum, limit=limit, offset=offset)
    return [alert.model_dump(mode="json") for alert in alerts]


@router.get("/{alert_id}", response_model=dict[str, Any])
async def get_alert(
    alert_id: str,
    db: DatabaseManager = Depends(get_db),
) -> dict[str, Any]:
    """Retrieve an intrusion alert by its unique alert_id."""
    alerts = db.list_alerts(limit=1000)
    for alert in alerts:
        if alert.alert_id == alert_id:
            return alert.model_dump(mode="json")
    raise HTTPException(status_code=404, detail=f"Alert with id '{alert_id}' not found")
