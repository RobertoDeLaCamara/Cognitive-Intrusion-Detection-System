# MCP Server — Conversational Alert Triage

**Audience:** SOC analysts, engineers integrating CNDS with an AI agent
**Module:** `src/mcp_server/` · **Tests:** `tests/test_mcp_server.py` · **Deps:** `requirements-mcp.txt`

CNDS exposes its alert store to [Model Context Protocol](https://modelcontextprotocol.io)
clients — Claude Code, Claude Desktop, or any MCP-compatible agent — as a set of
**read-only** tools. An analyst can then ask *"why did alert 431 fire, and has this host
done it before?"* instead of paging through JSON.

---

## Why this exists

CNDS is already five AI engines. Adding an LLM to *detect* would be redundant and
impossible on the hot path: flows expire against a 20,000-packet queue, and millions of
flows per day rule out per-flow inference on both latency and cost.

The actual bottleneck is downstream. Two mechanisms in CNDS are starved of human
judgement:

| Mechanism | What it waits for |
|---|---|
| `enrichment/adaptive_weights.py` | `ADAPTIVE_MIN_SAMPLES` (100) **acknowledged** alerts before weights adapt at all |
| `guardian/engine.py` | A human to confirm a block; otherwise every block silently rolls back after `GUARDIAN_BLOCK_MINUTES` |

Both need an analyst to decide *"true positive or not?"* — the expensive, tedious work
that in a home or lab deployment simply never happens. That is the gap this server
addresses: **triage and investigation, not detection and not enforcement.**

---

## Security model

Three structural controls, each verified by a test in `tests/test_mcp_server.py`.

### 1. Read-only is enforced by the database engine

Not by convention. `src/mcp_server/db.py` builds a dedicated engine where writes fail at
the driver level:

| Backend | Mechanism |
|---|---|
| SQLite | `PRAGMA query_only=ON` on every pooled connection |
| PostgreSQL | `postgresql_readonly` execution option → `SET TRANSACTION READ ONLY` |

A future editing mistake in a query function therefore cannot corrupt the alert store.
`TestReadOnlyGuarantees::test_sqlite_engine_rejects_writes` asserts a raw `INSERT` raises.
A second test greps `queries.py` for `db.add(`, `.commit()`, `delete(` and friends.

### 2. No tool actuates mitigation

There is deliberately **no** `block_ip`, `unblock_ip`, `acknowledge_alert` or
`create_suppression_rule` tool. The Guardian stays the sole decision maker for
enforcement: deterministic, unit-tested, circuit-broken and auditable. An agent may
explain and recommend; a human or the Guardian acts.

Replacing that with a non-deterministic LLM would be a security regression, not a
feature. `TestToolCatalogue::test_catalogue_exposes_only_read_verbs` fails the build if a
mutating tool is ever added.

### 3. Attacker-influenced data is bounded and tagged

Once alert fields reach an LLM, **the network becomes an input channel to the agent**. A
packet crafted to read like an instruction is a prompt-injection attempt delivered over
the wire.

Audited against the schema, what is actually attacker-influenced today is narrow:

| Field | Provenance | Handling |
|---|---|---|
| `src_ip`, `dst_ip` | Packet headers (spoofable) | Parsed with `ipaddress`; anything else returned as `[malformed-ip] …` |
| `ja3_string` | TLS ClientHello bytes | Checked against canonical JA3 syntax; otherwise `[non-canonical-ja3] …` |
| `ja3_hash` | MD5 of the above | Must be 32 hex chars, else `[malformed-ja3-hash] …` |
| `attack_type` | Model label / rule name | Scrubbed — closed vocabulary in practice, but stringly typed |
| `notes`, `reason` | Analyst free text | Scrubbed and length-bounded |

Not attacker-controlled, verified by reading the extractors: `triggered_rules` and
`payload_matches` hold **closed pattern names** (`sql_injection`, `xss`, …) chosen by
`features/payload_analyzer.py` — never raw payload bytes. Feature vectors are numeric,
`src_geo` comes from MaxMind, `mitre_techniques` from a static table. **Raw payload bytes
are never persisted.**

`sanitize.py` bounds length, strips control characters, and neutralises the delimiters
(code fences, angle brackets) needed to break out of a wrapper. Every payload carries
`_untrusted_fields` and an advisory note.

> It deliberately does **not** pattern-match for malicious intent. Regexing for "ignore
> previous instructions" is security theatre — trivially bypassed and it manufactures
> false confidence. The real control is control #2: a successful injection can mislead a
> summary, but there is no tool it can reach to unblock an IP.

### What is not protected

Anyone who can run this server can read every alert, the Guardian whitelist and the
detection thresholds. It is an **operator-local tool with no authentication** — the MCP
client spawns it as a subprocess over stdio and inherits the OS user's privileges. Do not
expose it over a network transport, and treat the DB file's permissions as the access
control boundary.

`get_detection_config` returns thresholds and policy but no credentials; a test asserts
no `password`/`token`/`secret`/`api_key` substring can appear in its output.

---

## Tool catalogue

Nine tools. All read-only, all returning JSON.

| Tool | Purpose |
|---|---|
| `list_alerts` | Alerts newest first. Filters: `severity`, `src_ip`, `acknowledged`, `attack_type`, `min_score`, `hours`, `limit`/`offset` |
| `get_alert` | One alert in full: per-engine scores, triggered rules, payload matches, MITRE techniques, GeoIP, JA3, plus any Guardian action it caused. `include_features` adds the 76+18 raw vectors |
| `get_ip_profile` | **The main triage tool.** Aggregate history for one source IP |
| `alert_trends` | Counts bucketed by `hour`/`day`, split by severity |
| `get_stats` | Totals, unacknowledged count, per-severity breakdown |
| `list_incidents` | Correlated incidents with linked alert counts |
| `list_mitigation_actions` | Guardian audit trail: what was blocked, why, and whether `pending`/`confirmed`/`undone`/`expired` |
| `list_suppression_rules` | Active suppressions — why an expected alert may be missing |
| `get_detection_config` | Thresholds, engine weights, critical rules, Guardian policy, IP lists |

Row counts are capped (`MAX_ROWS = 200`; `MAX_PROFILE_SCAN = 2000` rows scanned per
profile) so one broad question cannot flood the model's context.

### Input validation and error reporting

Every `src_ip` argument is validated with `ipaddress` and a malformed value is **rejected**
rather than queried. This is not pedantry: an unparseable address can only ever match zero
rows, and `total_alerts: 0` is indistinguishable from *"this host is known and clean"* — a
mistyped or hallucinated IP would otherwise read as an all-clear.

Failed calls are reported as protocol errors, not as content. Query functions raise
`QueryError` and `server.py` deliberately does **not** catch it: the SDK's `call_tool`
wrapper turns any exception into a `CallToolResult` with `isError=True`. Returning the
message as ordinary content would mark a failed call successful, and an agent could then
mistake the string `"No alert with id 999"` for data.

### Why `get_ip_profile` matters most

It answers the false-positive question in one call, returning: alert totals and
first/last seen, severity and attack-type breakdown, most frequent triggered rules,
targeted ports, distinct JA3 fingerprints, score max/mean, **how many of the host's past
alerts were acknowledged** (the best available proxy for earlier human verdicts), its
Guardian mitigation history, and the policy in force for it:

```json
"policy": {
  "guardian_enabled": true,
  "guardian_min_severity": "critical",
  "guardian_whitelisted": false,
  "detection_allowlisted": false,
  "detection_blocklisted": false
}
```

That last block saves the analyst from reading `.env` to find out why a critical alert
never produced a block.

### Why `get_detection_config` is not optional

An `ensemble_score` of 0.61 is uninterpretable in isolation. Against
`ENSEMBLE_THRESHOLD=0.55` it is marginal; and a `payload:sql_injection` hit fires an alert
through `CRITICAL_RULES` *regardless* of the weighted blend. Without this tool an agent
cannot distinguish "barely crossed the line" from "unambiguous signature match", and will
confidently mis-rank alerts.

---

## Setup

### 1. Install the SDK

```bash
pip install -r requirements-mcp.txt
```

Only the protocol SDK — the server reuses the SQLAlchemy/aiosqlite stack already pinned
in `requirements.txt`. Not needed by the detector, the API or the dashboard.

### 2. Verify it starts

```bash
python -m src.mcp_server      # blocks, waiting for JSON-RPC on stdin; Ctrl-C to exit
```

Logs go to **stderr**; stdout carries protocol frames only.

### 3. Register with a client

Point `DATABASE_URL` at the **absolute** path of the alert store so the working directory
cannot change which database is read:

```json
{
  "mcpServers": {
    "cnds": {
      "command": "/home/you/repos/cnds/venv/bin/python",
      "args": ["-m", "src.mcp_server"],
      "cwd": "/home/you/repos/cnds",
      "env": {
        "DATABASE_URL": "sqlite+aiosqlite:////home/you/repos/cnds/cnds.db"
      }
    }
  }
}
```

Note the four slashes in `sqlite+aiosqlite:////…` — three for the scheme plus the leading
`/` of an absolute path.

- **Claude Desktop:** add the block to `claude_desktop_config.json`, then restart it.
- **Claude Code:** put the same block in `.mcp.json` at the repo root, or register it with
  `claude mcp add`.

For a PostgreSQL deployment, give the server its **own** database role with only
`CONNECT` and `SELECT`. Read-only is already enforced client-side; a restricted role makes
it true server-side too.

---

## Suggested triage flow

The server ships this as MCP `instructions`, so a client receives it automatically:

1. `get_detection_config` once — establishes what the scores mean.
2. `list_alerts` with `acknowledged=false` — the untriaged queue.
3. `get_alert` on anything interesting — per-engine attribution.
4. `get_ip_profile` on the source IP — history and prior verdicts.
5. `list_mitigation_actions` / `list_suppression_rules` — what the Guardian already did
   and what is currently silenced.

Example questions this answers without writing a query:

- "Any critical alerts in the last 6 hours nobody has looked at?"
- "Explain alert 431 — which engines voted for it and how strongly?"
- "Is 192.168.1.74 a repeat offender or a device I've dismissed 20 times already?"
- "Which IPs is the Guardian blocking right now, and when do those blocks expire?"
- "Alert volume tripled yesterday — which attack type and which host?"

---

## Known limitations

| Limitation | Reason |
|---|---|
| No DNS query tool | `enrichment/dns_logger.py` keeps its log in an in-process `OrderedDict`, not the DB. A separate process cannot read it. Would need persistence or an HTTP call to the running API |
| No engine health tool | `/health` needs the loaded engine singletons; importing them would pull in torch and make the server heavy to spawn |
| No threat-intel lookup | Feeds live in an in-memory set inside the detector process, same constraint as the DNS log |
| No live capture stats | Held on `app.state` in the API process |
| Acknowledgement as FP proxy | `acknowledged` means "a human looked at it", not "confirmed false positive". A dedicated verdict field would be needed for a real signal |

None require a schema change to lift; all are consequences of running as a separate
process. An HTTP-backed variant could reach the in-memory ones, at the cost of requiring
the API to be up and holding a JWT.

---

## Extending it

Module layout, ordered by dependency:

```
src/mcp_server/
├── db.py         read-only engine + session factory  (only module touching connections)
├── sanitize.py   untrusted-field handling            (no imports from this package)
├── queries.py    async query functions               (take an AsyncSession, return dicts)
├── tools.py      JSON schemas + dispatch table       (no MCP SDK import)
└── server.py     MCP Server + stdio transport        (only module importing the SDK)
```

`queries.py` and `tools.py` are free of the SDK on purpose: the test suite exercises the
whole catalogue without the optional dependency installed.

To add a read tool:

1. Write `async def my_tool(db: AsyncSession, ...) -> dict` in `queries.py`. Route any
   attacker-influenced string through `sanitize` and tag the payload.
2. Append its schema to `TOOLS` and its handler to `HANDLERS` in `tools.py`. Schema
   property names **must** match the function's parameters — a test asserts this, since a
   mismatch would only surface as a runtime `TypeError`.
3. Add tests. `test_every_tool_is_callable_end_to_end` smoke-calls the catalogue, so a
   tool requiring new arguments must be registered in its `args` map.

Do not add a write tool. If enforcement from an agent is ever wanted, the right shape is
*propose, then let a human confirm* — the Telegram Confirm/Undo path in
`guardian/telegram_listener.py` already implements exactly that handshake.

---

## Testing

```bash
pytest tests/test_mcp_server.py -v
```

102 tests; the SDK is only needed for the protocol-level ones, which skip without it
(as does one PostgreSQL test without `asyncpg`). Coverage of the module: `sanitize.py`
100%, `queries.py` 99%, `tools.py` 97%; the remainder is stdio transport plumbing in
`server.py`.

`TestProtocolErrorSemantics` runs a real in-process client/server pair via the SDK's
`create_connected_server_and_client_session`, which is the only way to observe `isError`
— it is a property of the SDK wrapper around the handler, not of our own return value.

---

## Roadmap

This is phase 1 of three. Phases 2 and 3 are **not implemented**:

- **Phase 2 — triage agent.** An async consumer of `critical` alerts that writes an
  `analyst_summary` and a suggested verdict to a new column. It annotates; it does not
  act. This is what would finally feed `adaptive_weights` the acknowledged samples it
  waits for.
- **Phase 3 — propose-and-confirm.** Agent-suggested mitigations routed through the
  existing Telegram Confirm/Undo handshake, so a human remains the actuator.

Ship and live with phase 1 first: it costs nothing at runtime and reveals whether
conversational triage is genuinely useful before any autonomous loop is built.
