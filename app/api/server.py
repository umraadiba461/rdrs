"""REST API (FR-9). Run with:  uvicorn app.api.server:app"""
from __future__ import annotations

from typing import Optional

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel

from app.api import service
from app.core.config import load_config
from app.database.db import Database

CONFIG_PATH = "config.yaml"
REPORTS_DIR = "data/reports"

settings = load_config(CONFIG_PATH)
db = Database(settings.database_path)

app = FastAPI(title="RDRS API", description="Ransomware Detection and Response System")


class DetectionUpdate(BaseModel):
    window_seconds: Optional[int] = None
    files_modified_per_minute: Optional[int] = None
    renames_threshold: Optional[int] = None
    extension_changes_threshold: Optional[int] = None
    avg_entropy_threshold: Optional[float] = None


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/status")
def status():
    return service.get_status(db, settings.simulation_mode)


@app.get("/alerts")
def alerts(limit: int = Query(50, ge=1, le=500)):
    return service.get_recent(db, "alerts", limit)


@app.get("/events")
def events(limit: int = Query(50, ge=1, le=500)):
    return service.get_recent(db, "events", limit)


@app.get("/incidents")
def incidents(limit: int = Query(50, ge=1, le=500)):
    return service.get_recent(db, "incidents", limit)


@app.get("/reports")
def reports():
    return service.list_reports(REPORTS_DIR)


@app.post("/scan")
def scan():
    return service.run_scan(settings)


@app.get("/settings")
def get_settings():
    return {"simulation_mode": settings.simulation_mode,
            "detection": settings.detection.model_dump(),
            "weights": settings.weights.model_dump(),
            "levels": settings.levels.model_dump()}


@app.post("/settings")
def change_settings(update: DetectionUpdate):
    try:
        new_values = service.update_detection_settings(CONFIG_PATH, update.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return {"saved": new_values, "note": "Restart the monitor for the change to take effect"}