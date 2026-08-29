#!/usr/bin/env python3
"""
console/actions/base.py — the abstract connector interface for SOC response actions.

Stage C / C3-T1.
This module defines what an action connector *is* and how connectors are registered
and resolved by name. Runbooks bind connectors by name (e.g. "ssh_firewall", "firewall",
"notify", "mock"), so new connectors (e.g. OPNsense, Cloudflare, AWS WAF) can land
with zero changes to approvals, audit, eligibility, or the UI.

Core Contract:
  * `preview(params, context)` -> returns a safely REDACTED representation of the action.
    This is what reaches the UI, logs, and stored approval records.
  * `execute(params, context)` -> executes the action over the transport with unredacted
    parameters.
  * `revoke(params, context)` -> rolls back / undos the action atomically.
"""

from __future__ import annotations

import abc
from typing import Any, Dict, List, Optional, Type


class ActionError(Exception):
    """Base exception for action layer failures."""


class ConnectorNotFoundError(ActionError):
    """Raised when a requested connector name is not registered."""


class ActionValidationError(ActionError):
    """Raised when action parameters fail validation before execution."""


class ActionExecutionError(ActionError):
    """Raised when execution on the target system / transport fails."""


class ActionRevocationError(ActionError):
    """Raised when revocation on the target system / transport fails."""


class BaseConnector(abc.ABC):
    """Abstract connector interface for SOC response actions.

    Runbooks and approval records bind connectors by name. A connector
    knows how to preview an action (safely redacted), execute it on
    the target system (with unredacted parameters), and revoke it (rollback).
    """

    def __init__(self, name: str = "base", config: Optional[Dict[str, Any]] = None):
        self.name = name
        self.config = config or {}

    @abc.abstractmethod
    def preview(self, params: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Return a safe preview representation of the action.

        MUST pass all rendered commands, descriptions, and user-facing parameters
        through redact.redact_text() before returning. Raw IPs, credentials, or secrets
        must NEVER appear in preview output.

        Returns a dictionary with at least:
          - 'connector': str (connector identifier)
          - 'action': str (action name, e.g. 'block_ip')
          - 'description': str (human-readable summary, redacted)
          - 'command': str (rendered command / API call, redacted)
          - 'rollback_command': Optional[str] (rendered rollback command, redacted)
          - 'params': Dict[str, Any] (redacted parameter dictionary)
          - 'redacted': bool (must be True)
        """

    @abc.abstractmethod
    def execute(self, params: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Execute the action on the target system.

        Unredacted parameters travel ONLY over the secure local transport pipe
        (e.g. SSH subprocess pipe or HTTPS API call).

        Returns a dictionary with at least:
          - 'ok': bool
          - 'connector': str
          - 'action': str
          - 'output': str (verbatim command output / execution details)
          - 'error': Optional[str] (error message if failed)
        """

    @abc.abstractmethod
    def revoke(self, params: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Roll back / undo a previously executed action.

        Must be provably atomic and safe against touching bystander rules or state.

        Returns a dictionary with at least:
          - 'ok': bool
          - 'connector': str
          - 'action': str
          - 'output': str (verbatim output / revocation details)
          - 'error': Optional[str] (error message if failed)
        """


# -----------------------------------------------------------------------------
# Connector Registry
# -----------------------------------------------------------------------------

_REGISTRY: Dict[str, Type[BaseConnector]] = {}


def register_connector(name: str, connector_cls: Type[BaseConnector]) -> None:
    """Register a connector class under one or more names."""
    if not issubclass(connector_cls, BaseConnector):
        raise TypeError(f"Expected subclass of BaseConnector, got {connector_cls}")
    _REGISTRY[name] = connector_cls


def get_connector(name: str, config: Optional[Dict[str, Any]] = None) -> BaseConnector:
    """Instantiate a registered connector by name."""
    if name not in _REGISTRY:
        raise ConnectorNotFoundError(
            f"Connector '{name}' is not registered. Available connectors: {list_connectors()}"
        )
    cls = _REGISTRY[name]
    return cls(name=name, config=config)


def list_connectors() -> List[str]:
    """Return a sorted list of registered connector names."""
    return sorted(_REGISTRY.keys())


def clear_registry() -> None:
    """Reset the connector registry (used primarily in test teardown)."""
    _REGISTRY.clear()
