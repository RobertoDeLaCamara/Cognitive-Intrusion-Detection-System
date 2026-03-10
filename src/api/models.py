"""SQLAlchemy ORM models."""

import enum
from datetime import datetime, timezone
from sqlalchemy import (
    Column, Integer, String, Float, Boolean,
    DateTime, JSON, Enum as SAEnum, ForeignKey, Text,
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class SeverityLevel(str, enum.Enum):
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"


class IncidentStatus(str, enum.Enum):
    OPEN         = "open"
    INVESTIGATING = "investigating"
    RESOLVED     = "resolved"
    CLOSED       = "closed"


class Alert(Base):
    __tablename__ = "alerts"

    id               = Column(Integer, primary_key=True, index=True)
    timestamp        = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    src_ip           = Column(String(45), index=True)
    dst_ip           = Column(String(45), nullable=True)
    src_port         = Column(Integer, nullable=True)
    dst_port         = Column(Integer, nullable=True)
    protocol         = Column(Integer, nullable=True)   # IP proto number

    # Classification
    attack_type      = Column(String(100), nullable=True)  # from supervised engine
    severity         = Column(SAEnum(SeverityLevel), default=SeverityLevel.MEDIUM)

    # Ensemble
    ensemble_score   = Column(Float, nullable=True)
    engine_scores    = Column(JSON, nullable=True)   # {supervised, iforest, lstm, rules}
    triggered_rules  = Column(JSON, nullable=True)   # list of rule names

    # Raw features snapshot
    flow_features    = Column(JSON, nullable=True)
    host_features    = Column(JSON, nullable=True)
    payload_matches  = Column(JSON, nullable=True)

    # Workflow
    acknowledged     = Column(Boolean, default=False)
    notes            = Column(Text, nullable=True)
    incident_id      = Column(Integer, ForeignKey("incidents.id"), nullable=True)

    # GeoIP enrichment (Phase 8)
    src_geo          = Column(JSON, nullable=True)   # {country, city, latitude, longitude}

    # MITRE ATT&CK mapping
    mitre_techniques = Column(JSON, nullable=True)   # [{id, name, tactic}, ...]

    # JA3 TLS fingerprint
    ja3_hash         = Column(String(32), nullable=True, index=True)
    ja3_string       = Column(Text, nullable=True)

    incident         = relationship("Incident", back_populates="alerts")


class Incident(Base):
    __tablename__ = "incidents"

    id          = Column(Integer, primary_key=True, index=True)
    title       = Column(String(255))
    description = Column(Text, nullable=True)
    status      = Column(SAEnum(IncidentStatus), default=IncidentStatus.OPEN)
    severity    = Column(SAEnum(SeverityLevel), default=SeverityLevel.MEDIUM)
    assigned_to = Column(String(100), nullable=True)
    created_at  = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at  = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    resolved_at = Column(DateTime, nullable=True)
    notes       = Column(Text, nullable=True)

    alerts      = relationship("Alert", back_populates="incident")


class SuppressionRule(Base):
    """Temporary alert suppression filter (Phase 8)."""
    __tablename__ = "suppression_rules"

    id          = Column(Integer, primary_key=True, index=True)
    src_ip      = Column(String(45), nullable=True)
    dst_ip      = Column(String(45), nullable=True)
    attack_type = Column(String(100), nullable=True)
    min_severity = Column(String(20), nullable=True)
    reason      = Column(Text, nullable=True)
    created_at  = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at  = Column(DateTime, nullable=False, index=True)


class User(Base):
    """User accounts for JWT authentication."""
    __tablename__ = "users"

    id            = Column(Integer, primary_key=True, index=True)
    username      = Column(String(100), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role          = Column(String(20), default="viewer")  # admin, analyst, viewer
    is_active     = Column(Boolean, default=True)
    created_at    = Column(DateTime, default=lambda: datetime.now(timezone.utc))
