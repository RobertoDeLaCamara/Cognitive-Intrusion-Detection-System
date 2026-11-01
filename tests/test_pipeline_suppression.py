"""Suppression rules must apply to detector-written alerts, not only to /api/predict."""

import time
from datetime import timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import src.pipeline as pipeline
from src.api.models import Base, SuppressionRule
from src.enrichment.suppression import rule_matches
from src.timeutils import utcnow


def _rule(**kw):
    return SimpleNamespace(**{"src_ip": None, "dst_ip": None, "attack_type": None, "min_severity": None, **kw})


class TestRuleMatchesPort:

    def test_port_rule_matches_only_that_port(self):
        r = _rule(src_ip="10.0.0.1", dst_ip="10.0.0.2", dst_port=3128)
        assert rule_matches(r, "10.0.0.1", "10.0.0.2", None, "high", 3128)
        assert not rule_matches(r, "10.0.0.1", "10.0.0.2", None, "high", 22)

    def test_port_rule_does_not_match_a_flow_without_port(self):
        r = _rule(dst_ip="10.0.0.2", dst_port=53)
        assert not rule_matches(r, "10.0.0.1", "10.0.0.2", None, "low", None)

    def test_rule_without_port_matches_any_port(self):
        r = _rule(dst_ip="10.0.0.2")
        assert rule_matches(r, "10.0.0.1", "10.0.0.2", None, "low", 443)
        assert rule_matches(r, "10.0.0.1", "10.0.0.2", None, "low", None)

    def test_legacy_rule_object_without_dst_port_attribute(self):
        assert rule_matches(_rule(src_ip="a"), "a", "b", None, "low", 80)


class TestRuleMatches:
    def test_empty_rule_matches_everything(self):
        assert rule_matches(_rule(), "1.1.1.1", "2.2.2.2", "Generic", "critical")

    def test_dst_only(self):
        r = _rule(dst_ip="224.0.0.251")
        assert rule_matches(r, "9.9.9.9", "224.0.0.251", None, "medium")
        assert not rule_matches(r, "9.9.9.9", "10.0.0.1", None, "medium")

    def test_pair_must_match_both(self):
        r = _rule(src_ip="10.0.0.1", dst_ip="10.0.0.2")
        assert rule_matches(r, "10.0.0.1", "10.0.0.2", None, "low")
        assert not rule_matches(r, "10.0.0.3", "10.0.0.2", None, "low")

    def test_min_severity_is_a_ceiling(self):
        r = _rule(min_severity="high")
        assert rule_matches(r, "a", "b", None, "medium")
        assert rule_matches(r, "a", "b", None, "high")
        assert not rule_matches(r, "a", "b", None, "critical")


@pytest.fixture
def session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    pipeline._suppress_cache, pipeline._suppress_ts = [], 0.0
    yield s
    s.close()
    pipeline._suppress_cache, pipeline._suppress_ts = [], 0.0


def _args(src="10.0.0.1", dst="10.0.0.2", attack="Generic", severity="medium", dport=0):
    # FlowRecord.key = (src_ip, dst_ip, src_port, dst_port, protocol)
    rec = SimpleNamespace(src_ip=src, dst_ip=dst, key=(src, dst, 40000, dport, 6))
    return rec, SimpleNamespace(attack_type=attack), severity


class TestSuppressingRule:
    def test_active_rule_suppresses_but_critical_still_passes(self, session):
        session.add(SuppressionRule(dst_ip="10.0.0.2", min_severity="high", expires_at=utcnow() + timedelta(hours=1)))
        session.commit()
        rec, sc, _ = _args()
        assert pipeline._suppressing_rule(session, rec, sc, "medium") is not None
        assert pipeline._suppressing_rule(session, rec, sc, "critical") is None

    def test_port_limited_rule_only_suppresses_that_service(self, session):
        session.add(SuppressionRule(src_ip="10.0.0.1", dst_ip="10.0.0.2", dst_port=3128,
                                    expires_at=utcnow() + timedelta(hours=1)))
        session.commit()
        rec, sc, sev = _args(dport=3128)
        assert pipeline._suppressing_rule(session, rec, sc, sev) is not None
        rec, sc, sev = _args(dport=22)
        assert pipeline._suppressing_rule(session, rec, sc, sev) is None

    def test_expired_rule_ignored(self, session):
        session.add(SuppressionRule(dst_ip="10.0.0.2", expires_at=utcnow() - timedelta(minutes=1)))
        session.commit()
        rec, sc, sev = _args()
        assert pipeline._suppressing_rule(session, rec, sc, sev) is None

    def test_refresh_failure_keeps_stale_cache(self, session):
        rule = _rule(id=1, dst_ip="10.0.0.2")
        pipeline._suppress_cache, pipeline._suppress_ts = [rule], 0.0  # stale -> forces a refresh
        session.close()
        session.bind.dispose()
        session.get_bind().dispose()
        session.bind = None  # any query now raises
        rec, sc, sev = _args()
        assert pipeline._suppressing_rule(session, rec, sc, sev) is rule


class TestSuppressedLogLine:
    """A suppressed detector alert must be countable: "[SUPPRESSED] ... rule=#N" with the port."""

    def test_suppressed_alert_is_logged_with_tag_port_and_rule(self, caplog):
        import logging
        from unittest.mock import patch
        from sqlalchemy.pool import StaticPool
        from src.api.models import Alert
        from src.ensemble.scorer import EngineScores

        engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(engine)
        Session = sessionmaker(bind=engine)
        with Session() as s:
            s.add(SuppressionRule(src_ip="10.0.0.1", expires_at=utcnow() + timedelta(hours=1)))
            s.commit()
            rule_id = s.query(SuppressionRule).one().id
        pipeline._suppress_cache, pipeline._suppress_ts = [], 0.0
        flow = SimpleNamespace(src_ip="10.0.0.1", dst_ip="10.0.0.2", key=("10.0.0.1", "10.0.0.2", 40000, 3128, 6))
        scores = EngineScores()
        result = SimpleNamespace(score=0.8123)
        item = (flow, scores, result, "medium", [], None, None)
        with patch.object(pipeline, "_SessionLocal", Session), caplog.at_level(logging.INFO, logger="src.pipeline"):
            pipeline._write_alert(item)
        msgs = [r.getMessage() for r in caplog.records if "[SUPPRESSED]" in r.getMessage()]
        assert len(msgs) == 1
        assert "dport=3128" in msgs[0] and "score=0.812" in msgs[0] and f"rule=#{rule_id}" in msgs[0]
        with Session() as s:
            assert s.query(Alert).count() == 0
        pipeline._suppress_cache, pipeline._suppress_ts = [], 0.0
