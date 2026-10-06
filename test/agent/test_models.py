"""Model contract tests: validation, constraints, round-trip serialization."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from test.agent._fixtures import AgentTestCase, make_context  # noqa: E402


class ModelValidationTest(AgentTestCase):
    def test_agent_action_is_closed_vocabulary(self):
        from app.agent.models import AgentAction

        members = {m.value for m in AgentAction}
        self.assertIn("RESPOND", members)
        self.assertIn("DEFER_TO_VFS", members)
        self.assertIn("DEFER_TO_SECURITY", members)
        self.assertIn("SIMULATE_PERMISSION_RESULT", members)
        # The critical invariant: no host-execution member exists at all.
        for m in members:
            self.assertFalse(
                m.startswith(("EXECUTE", "RUN", "SHELL", "HOST")),
                f"host-execution action exists: {m}",
            )

    def test_confidence_is_bounded(self):
        from app.agent.models import AgentAction, AgentDecision

        with self.assertRaises(Exception):
            AgentDecision(action=AgentAction.RESPOND, confidence=1.5)
        with self.assertRaises(Exception):
            AgentDecision(action=AgentAction.RESPOND, confidence=-0.1)

    def test_decision_rejects_invalid_action(self):
        from app.agent.models import AgentDecision

        with self.assertRaises(Exception):
            AgentDecision(action="EXECUTE_ON_HOST")

    def test_decision_rejects_invalid_simulated_effect(self):
        from app.agent.models import AgentAction, AgentDecision

        with self.assertRaises(Exception):
            AgentDecision(action=AgentAction.RESPOND, simulated_effect="ROOT_SHELL")

    def test_environment_state_source_is_constrained(self):
        from app.agent.models import EnvironmentState

        with self.assertRaises(Exception):
            EnvironmentState(source="attacker_claimed")

    def test_state_update_allowlist_contains_only_cwd(self):
        from app.agent.models import STATE_UPDATE_ALLOWLIST

        self.assertEqual(set(STATE_UPDATE_ALLOWLIST), {"cwd"})


class ModelSerializationTest(AgentTestCase):
    def test_decision_round_trip(self):
        from app.agent.models import AgentAction, AgentDecision, DecisionSource

        decision = AgentDecision(
            action=AgentAction.SIMULATE_PERMISSION_RESULT,
            response="Permission denied",
            confidence=0.9,
            deception_category="privilege_escalation",
        )
        data = decision.model_dump(mode="json")
        self.assertEqual(data["action"], "SIMULATE_PERMISSION_RESULT")
        restored = AgentDecision.model_validate(data)
        self.assertEqual(restored, decision)

    def test_context_round_trip(self):
        context = make_context("ls -la")
        data = context.model_dump(mode="json")
        self.assertEqual(data["session_id"], "sess_test")
        self.assertEqual(data["environment_state"]["hostname"], "web-prod-01")
        restored = type(context).model_validate(data)
        self.assertEqual(restored.current_working_directory, "/home/admin")

    def test_event_names_are_stable(self):
        from app.agent.models import (
            EVENT_AGENT_DECISION,
            EVENT_AGENT_FALLBACK,
            EVENT_AGENT_GUARDRAIL_REJECT,
            EVENT_AGENT_INPUT_FLAG,
        )

        self.assertEqual(EVENT_AGENT_DECISION, "AGENT_DECISION")
        self.assertEqual(EVENT_AGENT_FALLBACK, "AGENT_FALLBACK")
        self.assertEqual(EVENT_AGENT_GUARDRAIL_REJECT, "AGENT_GUARDRAIL_REJECT")
        self.assertEqual(EVENT_AGENT_INPUT_FLAG, "AGENT_INPUT_FLAG")


class ResponsePlanTest(AgentTestCase):
    def test_build_response_plan_direct_output(self):
        from app.agent import build_response_plan
        from app.agent.models import AgentAction, AgentDecision, LatencyProfile

        decision = AgentDecision(
            session_id="s1",
            action=AgentAction.RESPOND,
            response="admin",
            confidence=0.95,
            latency_profile=LatencyProfile.FAST,
        )
        plan = build_response_plan(decision)
        self.assertEqual(plan.output, "admin")
        self.assertIsNone(plan.defer_to)
        self.assertIsNone(plan.new_cwd)
        self.assertEqual(plan.simulated_effect.value, "NONE")

    def test_build_response_plan_defers(self):
        from app.agent import build_response_plan
        from app.agent.models import AgentAction, AgentDecision

        for action, target in (
            (AgentAction.DEFER_TO_VFS, "vfs"),
            (AgentAction.DEFER_TO_SECURITY, "security"),
        ):
            decision = AgentDecision(session_id="s1", action=action, response="")
            plan = build_response_plan(decision)
            self.assertEqual(plan.defer_to, target)
            self.assertEqual(plan.output, "")

    def test_build_response_plan_state_updates_and_flags(self):
        from app.agent import build_response_plan
        from app.agent.models import AgentAction, AgentDecision

        decision = AgentDecision(
            session_id="s1",
            action=AgentAction.SIMULATE_DIRECTORY_OPERATION,
            response="",
            state_updates={"cwd": "/tmp"},
            security_flags=["PRIVILEGE_ESCALATION_ATTEMPT"],
        )
        plan = build_response_plan(decision)
        self.assertEqual(plan.new_cwd, "/tmp")
        self.assertIn("PRIVILEGE_ESCALATION_ATTEMPT", plan.security_flags)
        # flag events are structured for T1/T4
        self.assertTrue(any(e["event_type"] == "AGENT_SECURITY_FLAG" for e in plan.events))


if __name__ == "__main__":
    unittest.main()
