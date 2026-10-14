# Triage agent (MCP roadmap phase 2)

`src/triage/` annotates high-severity alerts with an **advisory** verdict,
evidence and a recommendation for the analyst. It is phase 2 of the roadmap in
[`mcp-server.md`](mcp-server.md): *it annotates; it does not act.*

```
alerts (unacknowledged, ≥ TRIAGE_MIN_SEVERITY, not yet annotated)
   │
   ▼
runner  ── builds context through the sanitising MCP query layer
   │        (get_alert + get_ip_profile: per-engine scores, rules, MITRE,
   │         Guardian actions, source history, whitelist policy)
   ▼
backend ── claude -p, structured output (JSON Schema), no built-in tools
   │        workflow mode: context in the prompt, zero tools
   │        agent mode:    alert id + read-only cnds MCP tools only
   ▼
schema.validate  →  policy.apply_guards  →  triage_annotations (append-only)
                                               │
                                               ▼
                         MCP get_alert → "agent_triage" (marked advisory)
```

## What it will never do

| Action | Who owns it |
|---|---|
| Acknowledge an alert, write `notes` | The analyst |
| Block / unblock / confirm a block | The Guardian (deterministic, circuit-broken) and the analyst via Telegram |
| Add a suppression rule | The analyst |
| Change weights, thresholds, lists | The analyst |

The runner writes **one** table, `triage_annotations`. A test walks the AST of
every module in `src/triage/` and fails if any of them imports the Guardian,
imports `MitigationAction`, or assigns to alert workflow fields.

## Why two modes

Anthropic's guidance on agents is to start with the simplest pattern that
works and add autonomy only when it measurably helps
([Building effective agents](https://www.anthropic.com/engineering/building-effective-agents)).

- **`workflow` (default)** — CNDS assembles the context deterministically and
  the model makes one call with **no tools**. Cheap, reproducible, and the
  attack surface is the prompt only.
- **`agent`** — the model gets the alert id and the nine read-only `cnds` MCP
  tools, and decides what to look up (incidents, suppressions, Guardian audit,
  detection config). More expensive and less predictable; use it when the
  evaluation shows `workflow` is missing context.

Run both on the same labelled set with `scripts/eval_triage.py` before
switching.

## Least privilege on the command line

`src/triage/backends.py` builds the `claude -p` invocation:

| Flag | Effect |
|---|---|
| `--bare` | Skips the host's hooks, skills, plugins, MCP servers, auto memory and CLAUDE.md. Requires `ANTHROPIC_API_KEY` (API billing, not your subscription). Turn off with `TRIAGE_CLAUDE_BARE=false`. |
| `--tools ""` | Removes every built-in tool: no shell, no file access, no web. |
| `--disallowedTools mcp__*` (workflow) | Removes MCP tools too. |
| `--mcp-config … --strict-mcp-config --allowedTools mcp__cnds` (agent) | Only the read-only cnds server is loaded and allowed. |
| `--permission-mode dontAsk` | Anything that would need approval is denied. |
| `--json-schema` | Output must match `src/triage/schema.py`; it is re-validated in Python anyway. |
| `--max-turns`, `--max-budget-usd` | Per-call turn and spend cap (`TRIAGE_MAX_TURNS`, `TRIAGE_MAX_USD_PER_ALERT`). |
| `--no-session-persistence` | Alert data does not end up in local transcripts. |

The process runs in an empty temporary directory, so nothing in the repo
(`.env` included) is reachable even if a tool slipped through.

## Prompt injection

Alert fields derived from traffic are attacker-influenced (see
`src/mcp_server/sanitize.py`). The triage agent inherits the phase-1 controls
and adds:

- the context is wrapped in `<cnds_data>` and the instructions say it is data;
  fields arrive with `_untrusted_fields` tags from the query layer;
- the model output is itself scrubbed (`policy.apply_guards`) before it is
  stored, because a summary can echo attacker text into the dashboard or into
  the next model that reads `get_alert`;
- above all, **a successful injection has nothing to actuate**. The worst case
  is a misleading annotation on an alert a human still has to acknowledge.

## Deterministic guards

`policy.apply_guards` runs on every schema-valid answer and records what it
changed in `policy_notes`. `model_verdict` keeps the raw model opinion.

| Guard | Rule |
|---|---|
| Confidence floor | `confidence < TRIAGE_MIN_CONFIDENCE` → verdict `needs_human` |
| No phantom mitigation | `confirm_block`/`undo_block` without a Guardian action on the alert → `escalate` |
| Whitelist | `confirm_block` on a Guardian-whitelisted source → `escalate` |
| Contradiction | `likely_benign` + `confirm_block` → `needs_human` + `escalate` |

Invalid output or a backend failure is stored too (`status` =
`invalid_output` / `backend_error`, verdict `needs_human`) so failures are
visible and are not retried in a loop. Re-run a specific alert with
`--alert-id`.

## Cost control

- Per call: `--max-budget-usd` (`TRIAGE_MAX_USD_PER_ALERT`, default 0.25).
- Per day: the runner sums `cost_usd` over the last 24 h and stops at
  `TRIAGE_DAILY_BUDGET_USD` (default 2.0); the rest waits for the next window.
- Per run: `TRIAGE_BATCH_SIZE` alerts at most.

`cost_usd` is the CLI's client-side estimate, good for budgeting, not billing.

## Running it

```bash
# one pass (cron / Jenkins / systemd timer)
ANTHROPIC_API_KEY=... python -m src.triage --once

# exercise the pipeline without calling a model
python -m src.triage --dry-run

# re-triage specific alerts in agent mode
TRIAGE_MCP_CONFIG=/opt/cnds/triage-mcp.json python -m src.triage --mode agent --alert-id 431 432

# long-running
python -m src.triage --loop
```

Agent-mode MCP config (absolute DB path, same as phase 1):

```json
{
  "mcpServers": {
    "cnds": {
      "command": "/opt/cnds/venv/bin/python",
      "args": ["-m", "src.mcp_server"],
      "cwd": "/opt/cnds",
      "env": { "DATABASE_URL": "sqlite+aiosqlite:////opt/cnds/cnds.db" }
    }
  }
}
```

The MCP server enforces read-only at the engine; the runner's own session is
the only writer, and it writes only `triage_annotations`.

## Measuring it

Ground truth comes from you: when you acknowledge an alert, start its notes
with `[tp]` or `[fp]`. Then:

```bash
python scripts/eval_triage.py            # table
python scripts/eval_triage.py --json     # for Grafana / CI
```

It reports coverage, deferral rate (`needs_human`), precision/recall of
`likely_malicious` on decided alerts, agreement, invalid/error count, how often
guards fired, and mean cost and latency. Start with ~20 labelled alerts; large
prompt or model changes show up even on a small set.

What to look for before trusting it more:

- precision of `likely_malicious` high **and** a deferral rate you can live
  with — an agent that defers everything is safe and useless;
- guards firing rarely — frequent guard hits mean the prompt and the policy
  disagree;
- `workflow` vs `agent` on the same labels — keep the simpler one unless the
  agent is clearly better.

## Phase 3 (not implemented)

Propose-and-confirm: route an agent `confirm_block`/`undo_block`
recommendation into the existing Telegram Confirm/Undo handshake, so the human
remains the actuator. Do it only after the evaluation above shows the
recommendations are worth a human's tap.
