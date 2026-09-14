"""Read-only Model Context Protocol (MCP) server for CNDS.

Exposes the alert store, Guardian mitigation history and detection
configuration to MCP clients (Claude Code, Claude Desktop, any MCP-compatible
agent) so an analyst can triage alerts conversationally.

Design constraints — deliberate, do not relax without reading doc/mcp-server.md:

* **Read-only.** Every tool is a SELECT. Read-only is enforced at the database
  engine level (see :mod:`src.mcp_server.db`), not merely by convention, so a
  future coding mistake cannot mutate the alert store.
* **No enforcement tools.** There is intentionally no block/unblock tool. The
  Guardian (``src/guardian/``) stays the sole, deterministic, auditable
  decision maker for mitigation. An agent may explain and recommend; it never
  actuates.
* **Off the hot path.** Like the Guardian, this server only reads rows that
  ``src/pipeline.py`` already committed. The packet-capture workers are never
  touched, and no LLM ever sits in the detection path.
* **Attacker-influenced data is tagged.** Fields an attacker can shape are
  routed through :mod:`src.mcp_server.sanitize` and marked untrusted before
  they reach a model context.

The package is named ``mcp_server`` rather than ``mcp`` so it cannot shadow
the ``mcp`` SDK distribution on ``sys.path``.
"""

__all__ = ["queries", "sanitize", "tools", "db"]
