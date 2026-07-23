from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import pytest

DEFAULT_TRACKING_URI = f"file://{Path(__file__).resolve().parent / 'mlruns'}"
DEFAULT_PROJECT_NAME = "ngn-sip-detect-defend"


@dataclass(frozen=True)
class MlflowTestConfig:
    tracking_uri: str
    project_name: str


@pytest.fixture(scope="session", autouse=True)
def configure_mlflow_env() -> MlflowTestConfig:
    """Set MLflow test defaults while allowing environment overrides."""
    tracking_uri = os.getenv("MLFLOW_TRACKING_URI", DEFAULT_TRACKING_URI)
    project_name = os.getenv("MLFLOW_PROJECT_NAME", DEFAULT_PROJECT_NAME)

    os.environ["MLFLOW_TRACKING_URI"] = tracking_uri
    os.environ["MLFLOW_PROJECT_NAME"] = project_name

    return MlflowTestConfig(tracking_uri=tracking_uri, project_name=project_name)
