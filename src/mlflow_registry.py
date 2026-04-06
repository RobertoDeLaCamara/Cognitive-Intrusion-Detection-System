"""Unified MLflow model registry for all CNDS models (Phase 5).

Provides a single interface to log, register, and load models from MLflow.
Falls back to local file paths when MLFLOW_TRACKING_URI is not set.
"""

import logging
import os
from typing import Optional

from .config import MLFLOW_TRACKING_URI, MLFLOW_REGISTRY_NAME

logger = logging.getLogger(__name__)

_mlflow = None


def _get_mlflow():
    """Lazy-import mlflow to avoid hard dependency."""
    global _mlflow
    if _mlflow is None:
        try:
            import mlflow
            _mlflow = mlflow
        except ImportError:
            _mlflow = False
    return _mlflow if _mlflow else None


def is_enabled() -> bool:
    return bool(MLFLOW_TRACKING_URI) and _get_mlflow() is not None


def init():
    """Initialize MLflow tracking if configured."""
    mlflow = _get_mlflow()
    if not MLFLOW_TRACKING_URI or mlflow is None:
        logger.info("MLflow disabled (no MLFLOW_TRACKING_URI or mlflow not installed)")
        return False
    # Unset system HTTP proxy so boto3 can reach the MinIO artifact store on LAN
    for _v in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        os.environ.pop(_v, None)
    mlflow.set_tracking_uri(MLFLOW_TRACKING_URI)
    logger.info("MLflow tracking: %s", MLFLOW_TRACKING_URI)
    return True


def log_model(model, artifact_path: str, model_name: str, metrics: Optional[dict] = None):
    """Log a model to MLflow and register it."""
    mlflow = _get_mlflow()
    if not is_enabled() or mlflow is None:
        return None
    try:
        with mlflow.start_run(run_name=f"register-{model_name}"):
            if metrics:
                mlflow.log_metrics(metrics)
            info = mlflow.sklearn.log_model(
                model, artifact_path=artifact_path,
                registered_model_name=f"{MLFLOW_REGISTRY_NAME}-{model_name}",
            )
            logger.info("Logged model %s: %s", model_name, info.model_uri)
            return info.model_uri
    except Exception as e:
        logger.error("MLflow log_model failed for %s: %s", model_name, e)
        return None


def load_latest(model_name: str, stage: str = "Production"):
    """Load the latest model version from the registry."""
    mlflow = _get_mlflow()
    if not is_enabled() or mlflow is None:
        return None
    try:
        model_uri = f"models:/{MLFLOW_REGISTRY_NAME}-{model_name}/{stage}"
        model = mlflow.sklearn.load_model(model_uri)
        logger.info("Loaded %s from MLflow (%s)", model_name, stage)
        return model
    except Exception as e:
        logger.debug("MLflow load failed for %s (falling back to local): %s", model_name, e)
        return None


def log_pytorch_model(model, artifact_path: str, model_name: str, metrics: Optional[dict] = None):
    """Log a PyTorch model to MLflow."""
    mlflow = _get_mlflow()
    if not is_enabled() or mlflow is None:
        return None
    try:
        with mlflow.start_run(run_name=f"register-{model_name}"):
            if metrics:
                mlflow.log_metrics(metrics)
            info = mlflow.pytorch.log_model(
                model, artifact_path=artifact_path,
                registered_model_name=f"{MLFLOW_REGISTRY_NAME}-{model_name}",
            )
            logger.info("Logged PyTorch model %s: %s", model_name, info.model_uri)
            return info.model_uri
    except Exception as e:
        logger.error("MLflow log_pytorch_model failed for %s: %s", model_name, e)
        return None


def load_latest_pytorch(model_name: str, stage: str = "Production"):
    """Load the latest PyTorch model from the registry."""
    mlflow = _get_mlflow()
    if not is_enabled() or mlflow is None:
        return None
    try:
        model_uri = f"models:/{MLFLOW_REGISTRY_NAME}-{model_name}/{stage}"
        model = mlflow.pytorch.load_model(model_uri)
        logger.info("Loaded PyTorch %s from MLflow (%s)", model_name, stage)
        return model
    except Exception as e:
        logger.debug("MLflow PyTorch load failed for %s: %s", model_name, e)
        return None
