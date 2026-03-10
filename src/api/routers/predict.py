"""Unified prediction endpoint — runs all engines and returns ensemble result."""

import logging
from datetime import datetime, timezone
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
import numpy as np

from ..database import get_db
from ..models import Alert, SeverityLevel
from ..schemas import PredictRequest, PredictResponse, EngineScoresOut
from .websocket import broadcast_alert
from ..metrics import inc_alert
from ...engines.registry import supervised as _supervised, iforest as _iforest, lstm as _lstm, rules as _rules, ensemble as _ensemble
from ...ensemble.scorer import EngineScores, severity_from_score
from ...features.flow_extractor import FlowRecord
from ...enrichment import geoip
from ...enrichment.correlation import correlate_alert
from ...enrichment.suppression import is_suppressed
from ...enrichment.notifications import notify_alert
from ...enrichment.confidence_decay import apply_decay
from ...enrichment.ip_lists import is_allowlisted, is_blocklisted
from ...config import ENSEMBLE_THRESHOLD

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api", tags=["predict"])


@router.post("/predict", response_model=PredictResponse)
async def predict(body: PredictRequest, db: AsyncSession = Depends(get_db)):
    # Allowlist: skip detection entirely
    if is_allowlisted(body.src_ip):
        return PredictResponse(
            src_ip=body.src_ip, ensemble_score=0.0, is_anomaly=False,
            severity="low", attack_type=None,
            engine_scores=EngineScoresOut(), active_engines=[], alert_id=None,
        )

    # Blocklist: auto-flag
    if is_blocklisted(body.src_ip):
        return PredictResponse(
            src_ip=body.src_ip, ensemble_score=1.0, is_anomaly=True,
            severity="critical", attack_type="Blocklisted",
            engine_scores=EngineScoresOut(), active_engines=["blocklist"], alert_id=None,
        )

    flow_vec  = np.array(body.flow_features,  dtype=np.float32) if body.flow_features  else None
    host_vec  = np.array(body.host_features,  dtype=np.float32) if body.host_features  else None
    pay_vec   = np.array(body.payload_features, dtype=np.float32) if body.payload_features else None
    payload   = body.payload_matches or []

    # --- Run all available engines ---
    scores = EngineScores()

    # Supervised (needs flow features)
    if flow_vec is not None and _supervised.is_available:
        result = _supervised.predict(flow_vec, pay_vec)
        if result:
            label, conf = result
            scores.supervised = 0.0 if label == "BENIGN" else conf
            scores.attack_type = label
            scores.supervised_confidence = conf
        else:
            scores.supervised = 0.0

    # Isolation Forest (needs host features)
    if host_vec is not None and _iforest.is_available:
        scores.isolation_forest = _iforest.anomaly_score(host_vec)

    # LSTM (needs host features in per-IP buffer)
    if host_vec is not None and _lstm.is_available:
        _lstm.update(body.src_ip, host_vec)
        scores.lstm = _lstm.anomaly_score(body.src_ip)

    # Rules (uses a minimal FlowRecord proxy or payload alone)
    if flow_vec is not None:
        proxy = FlowRecord(
            key=(body.src_ip, body.dst_ip or "", body.src_port or 0,
                 body.dst_port or 0, body.protocol or 0),
        )
        proxy.fwd_lengths = [int(flow_vec[3])] if flow_vec is not None else []
        proxy.start_time = 0.0
        proxy.last_time = float(flow_vec[0]) if flow_vec is not None else 1.0

        rule_score, triggered = _rules.evaluate(proxy, flow_vec, payload)
        scores.rules = rule_score
        scores.triggered_rules = triggered
    elif payload:
        scores.rules = 1.0
        scores.triggered_rules = [f"payload:{m}" for m in payload]

    # --- Ensemble ---
    result = _ensemble.score(scores)

    # Confidence decay for repeated alerts
    decayed_score = apply_decay(body.src_ip, result.score)
    result.score = decayed_score
    result.is_anomaly = decayed_score >= ENSEMBLE_THRESHOLD

    severity = severity_from_score(result.score, scores.attack_type)

    # GeoIP enrichment
    geo = geoip.lookup(body.src_ip)

    # --- Persist alert if anomaly ---
    alert_id = None
    if result.is_anomaly:
        alert = Alert(
            timestamp=datetime.now(timezone.utc),
            src_ip=body.src_ip,
            dst_ip=body.dst_ip,
            src_port=body.src_port,
            dst_port=body.dst_port,
            protocol=body.protocol,
            attack_type=scores.attack_type,
            severity=severity,
            ensemble_score=result.score,
            engine_scores={
                "supervised":       scores.supervised,
                "isolation_forest": scores.isolation_forest,
                "lstm":             scores.lstm,
                "rules":            scores.rules,
            },
            triggered_rules=scores.triggered_rules,
            flow_features=body.flow_features,
            host_features=body.host_features,
            payload_matches=payload,
            src_geo=geo,
        )
        db.add(alert)
        await db.flush()

        # Check suppression rules
        if await is_suppressed(alert, db):
            await db.rollback()
        else:
            # Alert correlation
            await correlate_alert(alert, db)
            await db.commit()
            await db.refresh(alert)
            alert_id = alert.id

            alert_payload = {
                "id": alert_id,
                "src_ip": body.src_ip,
                "dst_ip": body.dst_ip,
                "ensemble_score": result.score,
                "severity": severity,
                "attack_type": scores.attack_type,
                "triggered_rules": scores.triggered_rules,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "src_geo": geo,
            }
            await broadcast_alert(alert_payload)
            await notify_alert(alert_payload)
            inc_alert(severity)

    return PredictResponse(
        src_ip=body.src_ip,
        ensemble_score=result.score,
        is_anomaly=result.is_anomaly,
        severity=severity,
        attack_type=scores.attack_type,
        engine_scores=EngineScoresOut(
            supervised=scores.supervised,
            isolation_forest=scores.isolation_forest,
            lstm=scores.lstm,
            rules=scores.rules,
            attack_type=scores.attack_type,
            triggered_rules=scores.triggered_rules,
        ),
        active_engines=result.active_engines,
        alert_id=alert_id,
        src_geo=geo,
    )
