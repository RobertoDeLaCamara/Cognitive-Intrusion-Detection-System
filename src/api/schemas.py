"""Pydantic schemas for the Cognitive Network Defense System API."""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator
import ipaddress


# ── Prediction ────────────────────────────────────────────────────────────────

class PredictRequest(BaseModel):
    """Manual prediction from pre-extracted features (for testing/integration)."""
    src_ip: str
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[int] = None
    flow_features: Optional[List[float]] = Field(None, description="76 CICFlowMeter features", min_length=76, max_length=76)
    host_features: Optional[List[float]] = Field(None, description="18 host-level features", min_length=18, max_length=18)
    payload_features: Optional[List[float]] = Field(None, description="10 payload features", min_length=10, max_length=10)
    payload_matches: Optional[List[str]] = Field(default_factory=list)

    @field_validator("src_ip", "dst_ip", mode="before")
    @classmethod
    def validate_ip(cls, v):
        if v is None:
            return v
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"Invalid IP address: {v}")
        return v


class EngineScoresOut(BaseModel):
    supervised: Optional[float] = None
    isolation_forest: Optional[float] = None
    lstm: Optional[float] = None
    rules: Optional[float] = None
    attack_type: Optional[str] = None
    triggered_rules: List[str] = []


class PredictResponse(BaseModel):
    src_ip: str
    ensemble_score: float
    is_anomaly: bool
    severity: str
    attack_type: Optional[str]
    engine_scores: EngineScoresOut
    active_engines: List[str]
    alert_id: Optional[int] = None
    src_geo: Optional[Dict[str, Any]] = None
    mitre_techniques: Optional[List[Dict[str, str]]] = None
    ja3_hash: Optional[str] = None


# ── Alerts ─────────────────────────────────────────────────────────────────────

class AlertOut(BaseModel):
    id: int
    timestamp: datetime
    src_ip: str
    dst_ip: Optional[str]
    src_port: Optional[int]
    dst_port: Optional[int]
    attack_type: Optional[str]
    severity: str
    ensemble_score: Optional[float]
    engine_scores: Optional[Dict[str, Any]]
    triggered_rules: Optional[List[str]]
    acknowledged: bool
    notes: Optional[str]
    incident_id: Optional[int]
    src_geo: Optional[Dict[str, str]] = None
    mitre_techniques: Optional[List[Dict[str, str]]] = None
    ja3_hash: Optional[str] = None

    class Config:
        from_attributes = True


class AlertUpdate(BaseModel):
    acknowledged: Optional[bool] = None
    notes: Optional[str] = None
    incident_id: Optional[int] = None


# ── Incidents ──────────────────────────────────────────────────────────────────

class IncidentCreate(BaseModel):
    title: str
    description: Optional[str] = None
    severity: Optional[str] = "medium"
    assigned_to: Optional[str] = None


class IncidentOut(BaseModel):
    id: int
    title: str
    description: Optional[str]
    status: str
    severity: str
    assigned_to: Optional[str]
    created_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime]
    notes: Optional[str]

    class Config:
        from_attributes = True


# ── Health ─────────────────────────────────────────────────────────────────────

class HealthOut(BaseModel):
    status: str
    engines: Dict[str, bool]
    capture_stats: Optional[Dict[str, Any]] = None


# ── Suppression Rules (Phase 8) ───────────────────────────────────────────────

class SuppressionRuleCreate(BaseModel):
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    attack_type: Optional[str] = None
    min_severity: Optional[str] = Field(None, description="Suppress alerts at or below this severity level")
    reason: Optional[str] = None
    duration_minutes: int = Field(120, ge=1, le=10080, description="Duration in minutes (max 7 days)")


class SuppressionRuleOut(BaseModel):
    id: int
    src_ip: Optional[str]
    dst_ip: Optional[str]
    attack_type: Optional[str]
    min_severity: Optional[str]
    reason: Optional[str]
    created_at: datetime
    expires_at: datetime

    class Config:
        from_attributes = True
