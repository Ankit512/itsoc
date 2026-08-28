#!/usr/bin/env python3
"""
console/actions — the SOC response action connector layer.

Stage C / C3-T1.
Provides abstract connector interfaces and concrete connector implementations
for gated automated response actions (e.g. firewall element blocking via nftables/SSH).
"""

from .base import (
    ActionError,
    ConnectorNotFoundError,
    ActionValidationError,
    ActionExecutionError,
    ActionRevocationError,
    BaseConnector,
    register_connector,
    get_connector,
    list_connectors,
    clear_registry,
)
from .ssh_firewall import (
    SshFirewallConnector,
    TABLE_FAMILY,
    TABLE_NAME,
    CHAIN_NAME,
    SET_NAME,
    BOOTSTRAP_COMMANDS,
)

# Register default standard connectors
register_connector("ssh_firewall", SshFirewallConnector)
register_connector("firewall", SshFirewallConnector)

__all__ = [
    "ActionError",
    "ConnectorNotFoundError",
    "ActionValidationError",
    "ActionExecutionError",
    "ActionRevocationError",
    "BaseConnector",
    "SshFirewallConnector",
    "register_connector",
    "get_connector",
    "list_connectors",
    "clear_registry",
    "TABLE_FAMILY",
    "TABLE_NAME",
    "CHAIN_NAME",
    "SET_NAME",
    "BOOTSTRAP_COMMANDS",
]
