"""FastAPI application factory for HIDS monitoring control plane."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from hids.api.routes import alerts, events, fim, health
from hids.config.settings import Settings
from hids.db.database import DatabaseManager


def create_app(
    settings: Settings | None = None,
    db: DatabaseManager | None = None,
) -> FastAPI:
    """Create and configure FastAPI application for HIDS monitoring."""
    resolved_settings = settings or Settings()
    resolved_db = db or DatabaseManager(resolved_settings.db_path)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        resolved_db.init_db()
        app.state.settings = resolved_settings
        app.state.db = resolved_db
        yield

    app = FastAPI(
        title="Host Intrusion Detection System Control Plane",
        description="REST API for HIDS alerts, host telemetry events, and FIM baseline queries.",
        version="0.1.0",
        lifespan=lifespan,
    )

    # Attach initial state for immediate access in test fixtures before lifespan trigger
    app.state.settings = resolved_settings
    app.state.db = resolved_db

    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Register routers
    app.include_router(health.router)
    app.include_router(alerts.router)
    app.include_router(events.router)
    app.include_router(fim.router)

    return app
