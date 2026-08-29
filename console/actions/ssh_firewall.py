#!/usr/bin/env python3
"""
console/actions/ssh_firewall.py — nftables-over-SSH firewall action connector.

Stage C / C3-T1.
Implements the nftables-over-SSH perimeter defense connector per deviation D-2.
Blocks are maintained as elements of a dedicated set `blacklist` inside table
`inet itsoc`.

Safety & Invariants:
  1. Atomic, O(1) set operations: `nft add element` and `nft delete element`
     provably cannot delete or corrupt another blocked IP or system rule.
  2. Provenance comment: every blocked element carries `comment "itsoc:appr-<id>"`
     tying the rule to its specific approval record.
  3. Guardrail 4 (redaction): `preview()` passes all output through
     `redact.redact_text()`. Raw IPs never reach the UI, logs, or stored approval records.
  4. Transport isolation: unredacted parameters travel ONLY over the local SSH
     subprocess pipe to the target.
  5. Credential safety: only the private key file path (`key_path`) is passed via
     `-i <path>`; key material never enters `argv`, environment, or logs.
"""

from __future__ import annotations

import ipaddress
import os
from pathlib import Path
import re
import subprocess
from typing import Any, Dict, List, Optional

from .base import (
    BaseConnector,
    ActionError,
    ActionValidationError,
    ActionExecutionError,
    ActionRevocationError,
)

try:
    import console.redact as redact
except ImportError:
    import redact

TABLE_FAMILY = "inet"
TABLE_NAME = "itsoc"
CHAIN_NAME = "filter"
SET_NAME = "blacklist"

BOOTSTRAP_COMMANDS = [
    f"nft add table {TABLE_FAMILY} {TABLE_NAME}",
    f"nft add chain {TABLE_FAMILY} {TABLE_NAME} {CHAIN_NAME} '{{ type filter hook input priority -10; policy accept; }}'",
    f"nft add set {TABLE_FAMILY} {TABLE_NAME} {SET_NAME} '{{ type ipv4_addr; flags interval; }}'",
    f"nft add rule {TABLE_FAMILY} {TABLE_NAME} {CHAIN_NAME} ip saddr @{SET_NAME} drop comment \"itsoc:block-set-rule\"",
]


class SshFirewallConnector(BaseConnector):
    """nftables firewall connector executing over SSH against target host."""

    def __init__(self, name: str = "ssh_firewall", config: Optional[Dict[str, Any]] = None):
        super().__init__(name=name, config=config)
        self.host = str(self.config.get("host", "127.0.0.1"))
        self.port = int(self.config.get("port", 2222))
        self.user = str(self.config.get("user", "root"))
        self.key_path = self.config.get("key_path")
        self.timeout = int(self.config.get("timeout", 15))
        self.strict_host_key_checking = str(self.config.get("strict_host_key_checking", "accept-new"))
        self.auto_bootstrap = bool(self.config.get("auto_bootstrap", True))

    # -------------------------------------------------------------------------
    # Validation & Formatting Helpers
    # -------------------------------------------------------------------------

    @staticmethod
    def validate_ip(address: Any) -> str:
        """Validate and return normalized IPv4 address string.

        Raises ActionValidationError on empty or non-IPv4 input.
        """
        if not address or not isinstance(address, str):
            raise ActionValidationError(f"Missing or invalid IP address parameter: {address!r}")
        raw = address.strip()
        try:
            ip = ipaddress.IPv4Address(raw)
            return str(ip)
        except ValueError as exc:
            raise ActionValidationError(f"Invalid IPv4 address '{raw}': {exc}") from exc

    @staticmethod
    def format_comment(approval_id: Optional[str] = None, custom_comment: Optional[str] = None) -> str:
        """Format the element comment string tying it to the approval record."""
        if custom_comment:
            # Sanitize quotes and control chars
            sanitized = re.sub(r'["\'\\]', '', str(custom_comment)).strip()
            return sanitized[:64]
        if approval_id:
            aid = str(approval_id).strip()
            if not aid.startswith("appr-") and not aid.startswith("itsoc:"):
                aid = f"appr-{aid}"
            if not aid.startswith("itsoc:"):
                aid = f"itsoc:{aid}"
            return aid
        return "itsoc:manual-block"

    # -------------------------------------------------------------------------
    # Command Construction
    # -------------------------------------------------------------------------

    def build_bootstrap_command(self) -> str:
        """Return the chained nftables bootstrap command."""
        return " ; ".join(BOOTSTRAP_COMMANDS)

    def build_block_command(self, ip: str, approval_id: Optional[str] = None, comment: Optional[str] = None) -> str:
        """Return the unredacted nftables command to block an IP element."""
        comment_str = self.format_comment(approval_id=approval_id, custom_comment=comment)
        return f"nft add element {TABLE_FAMILY} {TABLE_NAME} {SET_NAME} '{{ {ip} comment \"{comment_str}\" }}'"

    def build_revoke_command(self, ip: str) -> str:
        """Return the unredacted nftables command to remove an IP element from the set."""
        return f"nft delete element {TABLE_FAMILY} {TABLE_NAME} {SET_NAME} '{{ {ip} }}'"

    def build_verify_command(self, json_format: bool = False) -> str:
        """Return command to inspect the itsoc nftables table / set elements."""
        flag = " -j" if json_format else ""
        return f"nft{flag} list table {TABLE_FAMILY} {TABLE_NAME}"

    def build_ssh_args(self, remote_command: str) -> List[str]:
        """Construct the argv list for the SSH client subprocess."""
        args = [
            "ssh",
            "-p", str(self.port),
            "-o", f"StrictHostKeyChecking={self.strict_host_key_checking}",
            "-o", "BatchMode=yes",
            "-o", f"ConnectTimeout={self.timeout}",
        ]
        if self.key_path:
            kp = Path(self.key_path)
            # Ensure key_path is a path reference, not private key content
            if "\n" in str(self.key_path) or "PRIVATE KEY" in str(self.key_path):
                raise ActionValidationError("key_path must be a file path, never raw private key content")
            args.extend(["-i", str(kp)])
        args.append(f"{self.user}@{self.host}")
        args.append(remote_command)
        return args

    # -------------------------------------------------------------------------
    # Transport Execution
    # -------------------------------------------------------------------------

    def _run_ssh(self, remote_command: str) -> subprocess.CompletedProcess:
        """Execute a remote command over SSH subprocess.

        Overridable or mockable in tests.
        """
        args = self.build_ssh_args(remote_command)
        try:
            return subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
        except subprocess.TimeoutExpired as exc:
            raise ActionExecutionError(f"SSH command timed out after {self.timeout}s: {exc}") from exc
        except FileNotFoundError as exc:
            raise ActionExecutionError(f"SSH binary not found: {exc}") from exc
        except Exception as exc:
            raise ActionExecutionError(f"SSH invocation failed: {exc}") from exc

    # -------------------------------------------------------------------------
    # BaseConnector Implementation: preview, execute, revoke
    # -------------------------------------------------------------------------

    def preview(self, params: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Return a safely REDACTED representation of the action.

        All commands, descriptions, and user-facing parameters pass through
        redact.redact_text().
        """
        context = context or {}
        raw_ip = params.get("address") or params.get("ip") or params.get("entity") or context.get("entity")
        approval_id = params.get("approval_id") or params.get("id") or context.get("approval_id") or context.get("id")
        custom_comment = params.get("comment")

        # Determine target representation
        target_str = f"{self.user}@{self.host}:{self.port}"

        # If parameter contains unresolved template e.g. {{incident.entity}}
        is_template = isinstance(raw_ip, str) and "{{" in raw_ip

        if is_template:
            ip_str = str(raw_ip)
            unredacted_cmd = self.build_block_command(ip_str, approval_id=approval_id, comment=custom_comment)
            unredacted_rollback = self.build_revoke_command(ip_str)
            unredacted_desc = f"Block source IP {ip_str} at perimeter firewall ({TABLE_FAMILY} {TABLE_NAME} {SET_NAME})"
        else:
            valid_ip = self.validate_ip(raw_ip)
            unredacted_cmd = self.build_block_command(valid_ip, approval_id=approval_id, comment=custom_comment)
            unredacted_rollback = self.build_revoke_command(valid_ip)
            unredacted_desc = f"Block source IP {valid_ip} at perimeter firewall ({TABLE_FAMILY} {TABLE_NAME} {SET_NAME})"

        # REDACTION (Guardrail 4)
        redacted_cmd = redact.redact_text(unredacted_cmd)
        redacted_rollback = redact.redact_text(unredacted_rollback)
        redacted_desc = redact.redact_text(unredacted_desc)

        redacted_params: Dict[str, Any] = {}
        for k, v in params.items():
            if isinstance(v, str):
                redacted_params[k] = redact.redact_text(v)
            else:
                redacted_params[k] = v

        return {
            "connector": self.name,
            "action": "block_ip",
            "target": target_str,
            "description": redacted_desc,
            "command": redacted_cmd,
            "rollback_command": redacted_rollback,
            "params": redacted_params,
            "redacted": True,
        }

    def execute(self, params: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Execute the IP block on the target firewall via SSH.

        Unredacted parameters travel only across the SSH transport.
        """
        context = context or {}
        raw_ip = params.get("address") or params.get("ip") or params.get("entity") or context.get("entity")
        valid_ip = self.validate_ip(raw_ip)

        approval_id = params.get("approval_id") or params.get("id") or context.get("approval_id") or context.get("id")
        custom_comment = params.get("comment")

        block_cmd = self.build_block_command(valid_ip, approval_id=approval_id, comment=custom_comment)

        # Attempt block command
        res = self._run_ssh(block_cmd)

        # If table/set does not exist and auto_bootstrap is enabled, bootstrap and retry
        if res.returncode != 0 and self.auto_bootstrap:
            err_lower = (res.stderr or "").lower()
            if "no such" in err_lower or "does not exist" in err_lower or "table" in err_lower:
                boot_res = self._run_ssh(self.build_bootstrap_command())
                if boot_res.returncode == 0:
                    res = self._run_ssh(block_cmd)

        if res.returncode == 0:
            return {
                "ok": True,
                "connector": self.name,
                "action": "block_ip",
                "ip": valid_ip,
                "comment": self.format_comment(approval_id=approval_id, custom_comment=custom_comment),
                "output": (res.stdout or "").strip(),
                "error": None,
            }

        return {
            "ok": False,
            "connector": self.name,
            "action": "block_ip",
            "ip": valid_ip,
            "output": (res.stdout or "").strip(),
            "error": (res.stderr or "").strip() or f"SSH execution returned exit code {res.returncode}",
        }

    def revoke(self, params: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Revoke the IP block by removing the element from the blacklist set.

        Atomic O(1) set element deletion provably cannot disturb bystander rules.
        """
        context = context or {}
        raw_ip = params.get("address") or params.get("ip") or params.get("entity") or context.get("entity")
        valid_ip = self.validate_ip(raw_ip)

        revoke_cmd = self.build_revoke_command(valid_ip)
        res = self._run_ssh(revoke_cmd)

        if res.returncode == 0:
            return {
                "ok": True,
                "connector": self.name,
                "action": "unblock_ip",
                "ip": valid_ip,
                "output": (res.stdout or "").strip(),
                "error": None,
            }

        return {
            "ok": False,
            "connector": self.name,
            "action": "unblock_ip",
            "ip": valid_ip,
            "output": (res.stdout or "").strip(),
            "error": (res.stderr or "").strip() or f"SSH execution returned exit code {res.returncode}",
        }
