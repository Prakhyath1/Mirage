"""Fallback tests: safe deterministic answers, zero host introspection."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from test.agent._fixtures import AgentTestCase, make_context  # noqa: E402


def _no_host_introspection():
    """Patch host introspection to explode — proving it is never called."""
    def boom(*args, **kwargs):
        raise AssertionError("fallback performed real host introspection")

    return (
        mock.patch("socket.gethostname", boom),
        mock.patch("os.uname", boom),
        mock.patch("os.getcwd", boom),
    )


class FallbackSafetyTest(AgentTestCase):
    def test_fallback_never_introspects_the_real_host(self):
        from app.agent.fallback import DeterministicFallback

        fallback = DeterministicFallback()
        patches = _no_host_introspection()
        with patches[0], patches[1], patches[2]:
            decision = fallback.build(make_context(), "whoami", "test")
        self.assertEqual(decision.response, "admin")

    def test_identity_answers_match_persona(self):
        from app.agent.fallback import DeterministicFallback
        from app.agent.models import AgentAction, DecisionSource

        fallback = DeterministicFallback()
        context = make_context()

        cases = {
            "whoami": "admin",
            "hostname": "web-prod-01",
            "pwd": "/home/admin",
            "arch": "x86_64",
        }
        for command, expected in cases.items():
            decision = fallback.build(context, command, "test")
            self.assertEqual(decision.response, expected, command)
            self.assertEqual(decision.action, AgentAction.RESPOND, command)

        decision = fallback.build(context, "uname -a", "test")
        self.assertIn("Linux web-prod-01", decision.response)
        self.assertEqual(decision.metadata.decision_source, DecisionSource.FALLBACK)
        self.assertTrue(decision.metadata.fallback)
        self.assertEqual(decision.metadata.fallback_reason, "test")

    def test_unknown_command_is_realistic_not_found_error(self):
        from app.agent.fallback import DeterministicFallback
        from app.agent.models import AgentAction, SimulatedEffect

        decision = DeterministicFallback().build(make_context(), "frobnicate", "test")
        self.assertEqual(decision.action, AgentAction.SIMULATE_ERROR)
        self.assertEqual(decision.simulated_effect, SimulatedEffect.ERROR)
        self.assertEqual(decision.response, "bash: frobnicate: command not found")

    def test_dangerous_command_under_containment_is_denied(self):
        from app.agent.fallback import DeterministicFallback
        from app.agent.models import AgentAction, BehaviorSignals, SimulatedEffect

        context = make_context()
        context.behavior_signals = BehaviorSignals(containment_active=True)
        decision = DeterministicFallback().build(context, "sudo cat /etc/shadow", "test")
        self.assertEqual(decision.action, AgentAction.SIMULATE_PERMISSION_RESULT)
        self.assertEqual(decision.simulated_effect, SimulatedEffect.PERMISSION_DENIED)
        self.assertIn("PRIVILEGE_ESCALATION_ATTEMPT", decision.security_flags)

    def test_dangerous_command_without_containment_still_flags(self):
        from app.agent.fallback import DeterministicFallback

        # rm -rf is destructive: flagged even when not contained
        decision = DeterministicFallback().build(make_context(), "rm -rf /data", "test")
        self.assertIn("DESTRUCTIVE_COMMAND", decision.security_flags)
        # and the fallback never claims the destructive action happened
        self.assertNotIn("removed", decision.response.lower())
        self.assertIn("command not found", decision.response)

    def test_empty_command_is_handled(self):
        from app.agent.fallback import DeterministicFallback

        decision = DeterministicFallback().build(make_context(), "", "test")
        self.assertEqual(decision.response, "bash: command: command not found")


if __name__ == "__main__":
    unittest.main()
