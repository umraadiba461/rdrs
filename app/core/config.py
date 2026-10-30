"""Configuration loader for RDRS (FR-1)."""
from __future__ import annotations

from pathlib import Path
from typing import List

import yaml
from pydantic import BaseModel, Field


class EntropyConfig(BaseModel):
    sample_bytes: int = 65536
    high_threshold: float = 7.5


class DetectionConfig(BaseModel):
    window_seconds: int = 60
    files_modified_per_minute: int = 20
    renames_threshold: int = 15
    extension_changes_threshold: int = 15
    avg_entropy_threshold: float = 7.0


class WeightsConfig(BaseModel):
    rapid_encryption: int = 40
    mass_rename: int = 30
    high_entropy: int = 25
    cpu_spike: int = 15
    unknown_program: int = 10


class LevelsConfig(BaseModel):
    warning: int = 40
    critical: int = 70


class LoggingConfig(BaseModel):
    dir: str = "./logs"
    rotation: str = "5 MB"
    retention: str = "10 days"


class Settings(BaseModel):
    watch_folders: List[str] = Field(default_factory=lambda: ["./data/sandbox"])
    simulation_mode: bool = True
    database_path: str = "./data/rdrs.db"
    quarantine_dir: str = "./data/quarantine"
    entropy: EntropyConfig = EntropyConfig()
    detection: DetectionConfig = DetectionConfig()
    weights: WeightsConfig = WeightsConfig()
    levels: LevelsConfig = LevelsConfig()
    logging: LoggingConfig = LoggingConfig()


def load_config(path: str | Path = "config.yaml") -> Settings:
    """Load and validate settings from a YAML file."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Config file not found: {p}")
    with p.open("r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}
    return Settings(**raw)
