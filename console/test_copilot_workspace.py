"""Regression coverage for the workspace-aware Copilot briefing.

Run with: python3 -m pytest console/test_copilot_workspace.py
"""

from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parent))
import copilot  # noqa: E402


def _state():
    return {
        "idle": False,
        "runId": "auth-demo",
        "sourceLabel": "auth.log",
        "linesParsed": 12,
        "findings": [{
            "id": "detector-0",
            "sev": "CRITICAL",
            "type": "auth_bruteforce_success",
            "title": "Brute-force then SUCCESSFUL login for 'admin' from 203.0.113.44",
            "host": "server-01",
            "occurrences": 6,
            "ruleWhy": "Failures then a success.",
            "mitre": [{"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"}],
            "lines": [{"n": 5, "a": "failed login from ", "hit": "203.0.113.44", "b": ""}],
        }],
        "events": [{
            "n": 5,
            "raw": "failed login for admin from 203.0.113.44",
            "host": "server-01",
            "findingId": "detector-0",
        }],
    }


class CopilotWorkspaceTest(unittest.TestCase):
    def test_explain_overview_returns_grounded_dashboard_and_next_steps(self):
        result = copilot.investigate(
            "Explain what is on this screen and what I should do next.",
            _state(),
            extras={
                "incidents": [{"id": "inc-1", "severity": "CRITICAL", "entity": "203.0.113.44", "findingIds": ["detector-0"]}],
                "assets": [{"name": "server-01", "maxSeverity": "CRITICAL"}],
                "users": [{"name": "admin", "maxSeverity": "CRITICAL"}],
                "ti": {"indicators": [], "indicatorSource": "offline"},
                "runbooks": {"runbooks": [{"id": "rb-block", "name": "Block source IP", "eligible": True}]},
                "forecast": {"phases": [], "note": "No later phases observed."},
                "cases": [{"id": "case-1", "title": "Auth follow-up", "status": "NEW", "assignee": ""}],
            },
            context={"screen": "Overview", "route": "/"},
        )

        self.assertIn("What the dashboard says", result["answer"])
        self.assertIn("Next best actions", result["answer"])
        self.assertIn("Ticket routing", result["answer"])
        self.assertIn("server-01", result["answer"])
        self.assertEqual(5, result["citations"][0]["n"])
        self.assertTrue(result["actions"])
        self.assertEqual("/alerts?sel=detector-0", result["actions"][0]["href"])


if __name__ == "__main__":
    unittest.main()
