"""_register_baseline must use only classic registry endpoints (MLflow 2.x server)."""
from unittest.mock import MagicMock

from src.unsupervised.artifact_schema import ARTIFACT_ROOT, MODEL_NAME
from src.unsupervised.window_trainer import _register_baseline


def _mlflow():
    m = MagicMock()
    return m, m.tracking.MlflowClient.return_value


def test_creates_version_from_run_artifact_uri():
    mlflow, client = _mlflow()
    _register_baseline(mlflow, "run1", "s3://b/12/run1/artifacts/")
    client.create_model_version.assert_called_once_with(
        name=MODEL_NAME, source=f"s3://b/12/run1/artifacts/{ARTIFACT_ROOT}", run_id="run1"
    )


def test_existing_registered_model_is_not_an_error():
    mlflow, client = _mlflow()
    client.create_registered_model.side_effect = RuntimeError("RESOURCE_ALREADY_EXISTS")
    _register_baseline(mlflow, "run1", "s3://b/12/run1/artifacts")
    client.create_model_version.assert_called_once()


def test_never_calls_register_model():
    mlflow, _ = _mlflow()
    _register_baseline(mlflow, "run1", "s3://b/x")
    mlflow.register_model.assert_not_called()
