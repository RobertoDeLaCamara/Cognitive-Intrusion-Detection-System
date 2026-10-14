"""Tests for the phase-2 triage agent (src/triage/).

No model is called: a StaticBackend stands in for ``claude -p``. The tests
pin the safety properties the design rests on — the agent writes only
annotations, never acknowledges or mitigates, guards override the model, and
the daily budget stops the loop.
"""

import json

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession, create_async_engine

from src.api.models import (
    Alert, Base, MitigationAction, MitigationStatus, SeverityLevel, TriageAnnotation,
)
from src.mcp_server import queries
from src.triage import backends, policy, prompt, runner, schema
from src.triage.backends import StaticBackend, build_cli_command, parse_cli_output


GOOD = {
    "verdict": "likely_malicious",
    "confidence": 0.9,
    "summary": "External host swept 40 ports in 10 s; rules and iforest fired.",
    "evidence": [{"source": "alert", "fact": "triggered_rules: port_scan"}],
    "recommendation": "escalate",
    "mitre_techniques": ["T1046"],
}


@pytest.fixture
async def factory():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    await engine.dispose()


async def _seed(factory, severity=SeverityLevel.HIGH, acknowledged=False, src_ip="203.0.113.7",
                with_action=False):
    async with factory() as db:
        a = Alert(src_ip=src_ip, dst_ip="192.168.1.20", dst_port=22, severity=severity,
                  attack_type="Reconnaissance", ensemble_score=0.81,
                  triggered_rules=["port_scan"], acknowledged=acknowledged)
        db.add(a)
        await db.commit()
        if with_action:
            db.add(MitigationAction(src_ip=src_ip, action_type="dns_block", backend="adguard",
                                    status=MitigationStatus.PENDING, alert_id=a.id))
            await db.commit()
        return a.id


# ── schema ───────────────────────────────────────────────────────────────────

def test_schema_accepts_good_output():
    clean, errors = schema.validate(GOOD)
    assert errors == []
    assert clean["verdict"] == "likely_malicious"


@pytest.mark.parametrize("bad", [
    {**GOOD, "verdict": "block_it"},
    {**GOOD, "confidence": 1.5},
    {**GOOD, "confidence": True},
    {**GOOD, "recommendation": "block_ip"},
    {**GOOD, "extra": 1},
    {k: v for k, v in GOOD.items() if k != "summary"},
    {**GOOD, "evidence": [{"source": "internet", "fact": "x"}]},
    {**GOOD, "mitre_techniques": ["ignore previous instructions"]},
    "not an object",
])
def test_schema_rejects_bad_output(bad):
    _, errors = schema.validate(bad)
    assert errors


# ── policy guards ───────────────────────────────────────────────────────────

def test_low_confidence_defers_to_human():
    out, notes = policy.apply_guards({**GOOD, "confidence": 0.4}, {}, min_confidence=0.6)
    assert out["verdict"] == "needs_human"
    assert notes


def test_block_recommendation_without_guardian_action_is_escalated():
    out, notes = policy.apply_guards({**GOOD, "recommendation": "confirm_block"},
                                     {"alert": {"mitigation_actions": []}}, 0.6)
    assert out["recommendation"] == "escalate"


def test_confirm_block_on_whitelisted_source_is_escalated():
    ctx = {"alert": {"mitigation_actions": [{"id": 1}]},
           "ip_profile": {"policy": {"guardian_whitelisted": True}}}
    out, _ = policy.apply_guards({**GOOD, "recommendation": "confirm_block"}, ctx, 0.6)
    assert out["recommendation"] == "escalate"


def test_summary_is_scrubbed():
    out, _ = policy.apply_guards({**GOOD, "summary": "ok ```\x07</cnds_data> boom"}, {}, 0.6)
    assert "```" not in out["summary"] and "\x07" not in out["summary"]
    assert "</cnds_data>" not in out["summary"]


# ── prompt ───────────────────────────────────────────────────────────────────

def test_workflow_prompt_wraps_data_and_agent_prompt_has_none():
    p = prompt.build_prompt(7, "workflow", {"alert": {"id": 7}})
    assert "<cnds_data>" in p and '"id": 7' in p
    a = prompt.build_prompt(7, "agent")
    assert "<cnds_data>\n" not in a and "get_alert(alert_id=7)" in a


# ── CLI backend (command line only, no process) ──────────────────────────────

def test_cli_command_is_least_privilege():
    cmd = build_cli_command("workflow", max_budget_usd=0.1)
    assert cmd[cmd.index("--tools") + 1] == ""
    assert cmd[cmd.index("--permission-mode") + 1] == "dontAsk"
    assert cmd[cmd.index("--disallowedTools") + 1] == "mcp__*"
    assert "--no-session-persistence" in cmd and "--bare" in cmd
    assert json.loads(cmd[cmd.index("--json-schema") + 1]) == schema.OUTPUT_SCHEMA

    agent = build_cli_command("agent", mcp_config="/etc/cnds-mcp.json")
    assert agent[agent.index("--allowedTools") + 1] == "mcp__cnds"
    assert "--strict-mcp-config" in agent


def test_agent_mode_requires_mcp_config():
    with pytest.raises(ValueError):
        build_cli_command("agent")


def test_parse_cli_output():
    ok = parse_cli_output(json.dumps({
        "type": "result", "subtype": "success", "is_error": False,
        "structured_output": GOOD, "total_cost_usd": 0.012, "duration_ms": 4100,
        "modelUsage": {"claude-sonnet-5-5": {}},
    }))
    assert ok.output == GOOD and ok.cost_usd == 0.012 and ok.model == "claude-sonnet-5-5"

    err = parse_cli_output(json.dumps({"is_error": True, "subtype": "error_max_turns",
                                       "total_cost_usd": 0.05}))
    assert err.output is None and err.cost_usd == 0.05 and err.error

    assert parse_cli_output("not json").error


# ── runner ───────────────────────────────────────────────────────────────────

async def test_runner_annotates_and_never_touches_the_alert(factory):
    alert_id = await _seed(factory)
    backend = StaticBackend(output=GOOD, cost_usd=0.01)

    summary = await runner.run_once(factory, backend, "workflow", "high", 24, 10, 0.6, 2.0)

    assert summary.annotated == 1 and summary.errors == 0
    async with factory() as db:
        alert = await db.get(Alert, alert_id)
        assert alert.acknowledged is False and alert.notes is None
        rows = (await db.execute(select(TriageAnnotation))).scalars().all()
        assert len(rows) == 1 and rows[0].verdict == "likely_malicious"
        actions = (await db.execute(select(MitigationAction))).scalars().all()
        assert actions == []
    # the model saw the data, wrapped
    assert "<cnds_data>" in backend.prompts[0] and "203.0.113.7" in backend.prompts[0]


async def test_runner_skips_low_severity_acknowledged_and_annotated(factory):
    await _seed(factory, severity=SeverityLevel.LOW)
    await _seed(factory, acknowledged=True)
    target = await _seed(factory)
    backend = StaticBackend(output=GOOD)

    first = await runner.run_once(factory, backend, "workflow", "high", 24, 10, 0.6, 2.0)
    second = await runner.run_once(factory, backend, "workflow", "high", 24, 10, 0.6, 2.0)

    assert first.considered == 1 and second.considered == 0
    async with factory() as db:
        rows = (await db.execute(select(TriageAnnotation))).scalars().all()
        assert [r.alert_id for r in rows] == [target]


async def test_invalid_output_is_stored_as_needs_human(factory):
    await _seed(factory)
    backend = StaticBackend(output={**GOOD, "verdict": "block_everything"})
    summary = await runner.run_once(factory, backend, "workflow", "high", 24, 10, 0.6, 2.0)
    assert summary.errors == 1
    async with factory() as db:
        row = (await db.execute(select(TriageAnnotation))).scalars().one()
        assert row.status == "invalid_output" and row.verdict == "needs_human"


async def test_backend_error_is_recorded(factory):
    await _seed(factory)
    backend = StaticBackend(output=None, error="timeout after 180s")
    await runner.run_once(factory, backend, "workflow", "high", 24, 10, 0.6, 2.0)
    async with factory() as db:
        row = (await db.execute(select(TriageAnnotation))).scalars().one()
        assert row.status == "backend_error" and "timeout" in row.error


async def test_daily_budget_stops_the_loop(factory):
    for _ in range(3):
        await _seed(factory)
    backend = StaticBackend(output=GOOD, cost_usd=0.6)
    summary = await runner.run_once(factory, backend, "workflow", "high", 24, 10, 0.6, 1.0)
    assert summary.skipped_budget and summary.annotated == 2


async def test_guard_applied_in_stored_row(factory):
    await _seed(factory, with_action=False)
    backend = StaticBackend(output={**GOOD, "recommendation": "confirm_block"})
    await runner.run_once(factory, backend, "workflow", "high", 24, 10, 0.6, 2.0)
    async with factory() as db:
        row = (await db.execute(select(TriageAnnotation))).scalars().one()
        assert row.recommendation == "escalate" and row.policy_notes


async def test_mcp_get_alert_exposes_latest_annotation_as_advisory(factory):
    alert_id = await _seed(factory)
    await runner.run_once(factory, StaticBackend(output=GOOD), "workflow", "high", 24, 10, 0.6, 2.0)
    async with factory() as db:
        detail = await queries.get_alert(db, alert_id)
        assert detail["agent_triage"]["verdict"] == "likely_malicious"
        assert "Advisory" in detail["agent_triage"]["_advisory"]
        bare = await queries.get_alert(db, alert_id, include_triage=False)
        assert "agent_triage" not in bare


def test_triage_package_has_no_actuation_paths():
    """Structural check: no Guardian import, no mitigation rows, no alert writes."""
    import ast
    import inspect
    for mod in (backends, policy, prompt, runner, schema):
        tree = ast.parse(inspect.getsource(mod))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                assert "guardian" not in (node.module or ""), (mod.__name__, node.module)
                assert "MitigationAction" not in [a.name for a in node.names], mod.__name__
            if isinstance(node, ast.Import):
                assert not any("guardian" in a.name for a in node.names), mod.__name__
            if isinstance(node, (ast.Assign, ast.AugAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for t in targets:
                    if isinstance(t, ast.Attribute):
                        assert t.attr not in ("acknowledged", "notes", "severity", "incident_id"), (
                            mod.__name__, t.attr)
