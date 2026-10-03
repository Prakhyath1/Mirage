"""Guardrail tests: rejections, allowlists, evaluator interface."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from test.agent._fixtures import AgentTestCase, make_context  # noqa: E402


class GuardrailRejectionTest(AgentTestCase):
    def test_unknown_action_rejected(self):
        from app.agent.guardrails import RuleGuardrail
        from app.agent.models import AgentDecision

        # A real AgentDecision cannot hold an invalid action (pydantic closes
        # the vocabulary at construction). model_construct simulates the
        # defense-in-depth case: a corrupted object reaching the guardrail.
        bad = AgentDecision.model_construct(_fields_set=set(), action="EXECUTE_HOST_COMMAND", response="ok")
        result = RuleGuardrail().evaluate(bad, make_context())
        self.assertEqual(result.status.value, "REJECTED")
        self.assertIn("action_allowlist", result.rule_hits)

    def test_unknown_tool_rejected(self):
        from app.agent.guardrails import RuleGuardrail
        from app.agent.models import AgentAction, AgentDecision

        bad = AgentDecision(
            action=AgentAction.RESPOND,
            response="x",
            requested_tools=["shell_exec"],
        )
        result = RuleGuardrail().evaluate(bad, make_context())
        self.assertEqual(result.status.value, "REJECTED")
        self.assertIn("tool_allowlist", result.rule_hits)

    def test_known_tool_passes_tool_allowlist(self):
        from app.agent.tools import get_tool_registry
        from app.agent.guardrails import RuleGuardrail
        from app.agent.models import AgentAction, AgentDecision

        known = get_tool_registry().names()
        self.assertTrue(known, "default registry must not be empty")
        good = AgentDecision(
            action=AgentAction.RESPOND,
            response="x",
            requested_tools=[known[0]],
        )
        result = RuleGuardrail().evaluate(good, make_context())
        self.assertNotIn("tool_allowlist", result.rule_hits)

    def test_oversized_response_rejected(self):
        from app.agent.config import AgentConfig
        from app.agent.guardrails import RuleGuardrail
        from app.agent.models import AgentAction, AgentDecision

        bad = AgentDecision(
            action=AgentAction.RESPOND, response="x" * 500
        )
        result = RuleGuardrail(config=AgentConfig(agent_max_response=100)).evaluate(
            bad, make_context()
        )
        self.assertEqual(result.status.value, "REJECTED")
        self.assertIn("response_size_bound", result.rule_hits)

    def test_illegal_state_update_rejected(self):
        from app.agent.guardrails import RuleGuardrail
        from app.agent.models import AgentAction, AgentDecision

        bad = AgentDecision(
            action=AgentAction.SIMULATE_FILE_OPERATION,
            response="ok",
            state_updates={"uid": "0"},
        )
        result = RuleGuardrail().evaluate(bad, make_context())
        self.assertEqual(result.status.value, "REJECTED")
        self.assertIn("state_update_allowlist", result.rule_hits)

    def test_cwd_state_update_allowed(self):
        from app.agent.guardrails import RuleGuardrail
        from app.agent.models import AgentAction, AgentDecision

        good = AgentDecision(
            action=AgentAction.SIMULATE_DIRECTORY_OPERATION,
            response="",
            state_updates={"cwd": "/tmp"},
        )
        result = RuleGuardrail().evaluate(good, make_context())
        self.assertEqual(result.status.value, "APPROVED")

    def test_host_execution_semantics_rejected(self):
        from app.agent.guardrails import RuleGuardrail
        from app.agent.models import AgentAction, AgentDecision

        bad = AgentDecision(
            action=AgentAction.RESPOND,
            response="running via os.system for you",
        )
        result = RuleGuardrail().evaluate(bad, make_context())
        self.assertEqual(result.status.value, "REJECTED")
        self.assertIn("no_host_execution", result.rule_hits)

    def test_ai_self_reference_is_deception_break(self):
        from app.agent.guardrails import RuleGuardrail
        from app.agent.models import AgentAction, AgentDecision

        bad = AgentDecision(
            action=AgentAction.RESPOND, response="As an AI, I cannot run that."
        )
        result = RuleGuardrail().evaluate(bad, make_context())
        self.assertEqual(result.status.value, "REJECTED")
        self.assertIn("deception_break", result.rule_hits)

    def test_honeypot_mention_is_deception_break(self):
        from app.agent.guardrails import RuleGuardrail
        from app.agent.models import AgentAction, AgentDecision

        bad = AgentDecision(
            action=AgentAction.RESPOND, response="this is a honeypot, bye"
        )
        result = RuleGuardrail().evaluate(bad, make_context())
        self.assertEqual(result.status.value, "REJECTED")
        self.assertIn("deception_break", result.rule_hits)

    def test_defer_may_not_update_state(self):
        from app.agent.guardrails import RuleGuardrail
        from app.agent.models import AgentAction, AgentDecision

        bad = AgentDecision(
            action=AgentAction.DEFER_TO_VFS,
            state_updates={"cwd": "/tmp"},
        )
        result = RuleGuardrail().evaluate(bad, make_context())
        self.assertEqual(result.status.value, "REJECTED")
        self.assertIn("defer_clean", result.rule_hits)

    def test_noop_may_not_update_state(self):
        from app.agent.guardrails import RuleGuardrail
        from app.agent.models import AgentAction, AgentDecision

        bad = AgentDecision(
            action=AgentAction.NOOP,
            response="",
            state_updates={"cwd": "/tmp"},
        )
        result = RuleGuardrail().evaluate(bad, make_context())
        self.assertEqual(result.status.value, "REJECTED")
        self.assertIn("noop_clean", result.rule_hits)


class GuardrailEngineTest(AgentTestCase):
    def test_review_approved_returns_same_decision(self):
        from app.agent.guardrails import GuardrailEngine
        from app.agent.models import AgentAction, AgentDecision

        good = AgentDecision(action=AgentAction.RESPOND, response="ubuntu")
        engine = GuardrailEngine()
        out = engine.review(good, make_context())
        self.assertIs(out, good)
        self.assertEqual(engine.approvals, 1)

    def test_review_rejected_replaced_by_fallback(self):
        from app.agent.guardrails import GuardrailEngine
        from app.agent.models import AgentDecision, DecisionSource

        bad = AgentDecision.model_construct(
            _fields_set=set(), action="NOT_AN_ACTION", response="x"
        )
        engine = GuardrailEngine()
        out = engine.review(bad, make_context())
        self.assertIsNot(out, bad)
        self.assertTrue(out.metadata.fallback)
        self.assertEqual(out.metadata.decision_source, DecisionSource.FALLBACK)
        self.assertEqual(engine.rejections, 1)
        # The rejection reason is carried in metadata for T4
        self.assertIn("unknown action", out.metadata.fallback_reason)

    def test_custom_evaluator_can_be_slotted_in(self):
        from app.agent.guardrails import DecisionEvaluator, GuardrailEngine
        from app.agent.models import (
            AgentAction,
            AgentDecision,
            GuardrailResult,
            GuardrailStatus,
        )

        class AlwaysReject(DecisionEvaluator):
            def evaluate(self, decision, context):
                return GuardrailResult(
                    status=GuardrailStatus.REJECTED,
                    reasons=["policy"],
                    rule_hits=["test_rule"],
                )

        engine = GuardrailEngine(evaluator=AlwaysReject())
        out = engine.review(
            AgentDecision(action=AgentAction.RESPOND, response="x"), make_context()
        )
        self.assertTrue(out.metadata.fallback)
        self.assertEqual(engine.rejections, 1)


if __name__ == "__main__":
    unittest.main()
