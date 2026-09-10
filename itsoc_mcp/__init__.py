"""itsoc_mcp — an MCP server over the local log-analysis backend with no action execution and no approval authority.

This package exposes the project's EXISTING analysis capabilities as MCP tools so
an MCP-capable agent (Claude Code / Desktop) can call them. It is a *client* of
the already-running local backend (http://127.0.0.1:8765 by default; override with
ITSOC_BASE_URL). It computes NO verdicts of its own: severities, correlation, and
the rule verdicts are all owned by the frozen deterministic engine on the backend.
This layer has no action execution and no approval authority: it can propose
perimeter actions in a 'pending' state via propose_block_ip, but execution and
approval strictly require human-in-the-loop step-up authentication on the backend console.

Honesty is the whole point of the package:
  * Verdicts stay rule-owned; explanations are advisory; MITRE tags are derived.
  * Raw log text passes through console/redact.py before it leaves, UNLESS
    ITSOC_MCP_TRUSTED_LOCAL=1 is set (see itsoc_mcp.redaction).
  * Backend null / "0 lines parsed" / idle states are passed through verbatim —
    never a fabricated all-clear or an empty file dressed up as success.
"""

__version__ = "0.2.0"
