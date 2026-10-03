"""Persona tests: consistency, env overrides, determinism (no randomness)."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from test.agent._fixtures import AgentTestCase  # noqa: E402


class PersonaConsistencyTest(AgentTestCase):
    def test_get_persona_is_stable_across_calls(self):
        from app.agent.persona import PersonaEngine

        engine = PersonaEngine()
        self.assertIs(engine.get_persona(), engine.get_persona())

    def test_two_engines_same_env_agree(self):
        from app.agent.persona import PersonaEngine

        p1 = PersonaEngine().get_persona()
        p2 = PersonaEngine().get_persona()
        self.assertEqual(p1, p2)

    def test_persona_fields_are_complete(self):
        from app.agent.persona import PersonaEngine

        p = PersonaEngine().get_persona()
        for field in ("hostname", "distribution", "kernel", "arch", "username",
                      "uid", "gid", "home", "shell", "system_role", "organization"):
            self.assertTrue(getattr(p, field), f"empty persona field: {field}")
        self.assertEqual(p.home, f"/home/{p.username}")

    def test_services_match_role(self):
        from app.agent.persona import PersonaEngine

        p = PersonaEngine().get_persona()
        self.assertIn("ssh", p.services)
        role = p.system_role.lower()
        if "nginx" in role:
            self.assertIn("nginx", p.services)


class PersonaEnvOverrideTest(AgentTestCase):
    def test_env_overrides_change_persona(self):
        import os
        from app.agent.persona import PersonaEngine

        base = PersonaEngine().get_persona()
        os.environ["MIRAGE_PERSONA_HOSTNAME"] = "db-prod-09"
        os.environ["MIRAGE_PERSONA_ROLE"] = "database server (mysql + postgres)"
        os.environ["MIRAGE_PERSONA_UID"] = "0"

        from app.agent.config import reset_agent_config
        reset_agent_config()
        overridden = PersonaEngine().get_persona()

        self.assertEqual(overridden.hostname, "db-prod-09")
        self.assertNotEqual(overridden.hostname, base.hostname)
        self.assertEqual(overridden.uid, 0)
        # Role change flows into services
        self.assertIn("mysql", overridden.services)

    def test_invalid_env_int_falls_back_to_default(self):
        import os as _os
        from app.agent.persona import PersonaEngine

        _os.environ["MIRAGE_PERSONA_UID"] = "not-a-number"
        from app.agent.config import reset_agent_config
        reset_agent_config()
        p = PersonaEngine().get_persona()
        self.assertEqual(p.uid, 1000)


class SimulatedClockTest(AgentTestCase):
    """date/uptime must track the live clock: no frozen 2026-09-30 constant."""

    def test_date_matches_real_clock(self):
        from datetime import datetime, timedelta, timezone

        from app.agent.persona import simulated_date_string, simulated_now

        before = simulated_now()
        rendered = simulated_date_string()
        after = simulated_now()

        # rendered date must parse back to the current wall time. The format
        # is classic Unix with a space-padded day ('Oct  2'), so normalize
        # internal runs of spaces before parsing.
        parts = " ".join(rendered.split())
        # 'Fri Oct 2 09:15:07 UTC 2026'
        parsed = datetime.strptime(parts, "%a %b %d %H:%M:%S UTC %Y").replace(
            tzinfo=timezone.utc
        )
        self.assertTrue(
            before - timedelta(seconds=2) <= parsed <= after + timedelta(seconds=2),
            f"rendered date {rendered!r} not between {before} and {after}",
        )

    def test_date_string_format_is_classic_unix(self):
        from app.agent.persona import simulated_date_string

        rendered = simulated_date_string()
        # e.g. 'Fri Oct  2 09:15:07 UTC 2026' (single-digit day, double space ok)
        self.assertRegex(rendered, r"^\w{3} \w{3} +\d+ \d{2}:\d{2}:\d{2} UTC \d{4}$")
        self.assertIn("UTC", rendered)

    def test_uptime_advances_with_elapsed_time(self):
        import time as _time

        from app.agent import persona as persona_mod
        from app.agent.persona import simulated_uptime_string

        first = simulated_uptime_string("web-prod-01")
        # uptime's minute counter is minute-granular: shift the simulated
        # boot epoch back one minute and confirm the string tracks elapsed
        # time instead of being a frozen constant.
        original = persona_mod._SIM_BOOT_EPOCH
        try:
            persona_mod._SIM_BOOT_EPOCH = original - 60
            second = simulated_uptime_string("web-prod-01")
        finally:
            persona_mod._SIM_BOOT_EPOCH = original

        self.assertIn("web-prod-01", first)
        self.assertIn("load average", first)
        # uptime must advance as the process lives, never frozen
        self.assertNotEqual(first, second)

    def test_uptime_format_matches_real_command(self):
        from app.agent.persona import simulated_uptime_string

        rendered = simulated_uptime_string("web-prod-01")
        # ' web-prod-01 up 14:23,  1 user,  load average: 0.08, 0.03, 0.05'
        self.assertRegex(
            rendered,
            r"^ \S+ up .+, +1 user, +load average: "
            r"\d+\.\d+, \d+\.\d+, \d+\.\d+$",
        )

    def test_identity_and_fallback_agree_on_clock(self):
        """decision.py and fallback.py must produce identical date output."""
        from app.agent.decision import DecisionEngine
        from app.agent.fallback import DeterministicFallback
        from test.agent._fixtures import make_context

        context = make_context()
        via_decision = DecisionEngine().decide_deterministic(context, "date")
        via_fallback = DeterministicFallback().build(context, "date", "test")
        self.assertEqual(via_decision.response, via_fallback.response)

    def test_uptime_agrees_between_paths(self):
        from app.agent.decision import DecisionEngine
        from app.agent.fallback import DeterministicFallback
        from test.agent._fixtures import make_context

        context = make_context()
        via_decision = DecisionEngine().decide_deterministic(context, "uptime")
        via_fallback = DeterministicFallback().build(context, "uptime", "test")
        self.assertEqual(via_decision.response, via_fallback.response)


if __name__ == "__main__":
    unittest.main()
