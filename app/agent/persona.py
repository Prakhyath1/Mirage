"""Persona engine: the consistent identity of the simulated host.

Consistency beats randomness. The persona is derived once per process from
configuration (environment variables) and is stable for the lifetime of the
engine. T3 will own the authoritative environment; until it provides one, the
persona is the explicit, marked fallback source for environment state.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import List, Optional

from .config import AgentConfig, get_agent_config
from .models import EnvironmentState, PersonaState, SimulatedUser

# Process boot time of the simulated machine: fixed at import so ``uptime``
# advances believably across the running process instead of freezing at a
# constant value. Deliberately not the real host's boot time.
_SIM_BOOT_EPOCH = time.time() - 14 * 3600 - 23 * 60


def simulated_now() -> datetime:
    """Current wall-clock time of the simulated machine (UTC, host clock).

    ``date`` must agree with the attacker's own clock, so the live system
    clock is used directly — only the timezone is fixed to UTC.
    """
    return datetime.now(timezone.utc)


def simulated_date_string() -> str:
    """``date`` output in classic Unix format, e.g. 'Fri Oct  2 09:15:07 UTC 2026'."""
    now = simulated_now()
    return now.strftime("%a %b %e %H:%M:%S UTC %Y").replace("  ", " ")


def simulated_uptime_string(hostname: str) -> str:
    """``uptime`` output consistent with the running process's boot time.

    Uptime advances as the process lives and the load average wiggles within
    a believable band — never a frozen constant. No real host load data is
    disclosed; only persona values plus elapsed time.
    """
    up_seconds = int(time.time() - _SIM_BOOT_EPOCH)
    days, rem = divmod(up_seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60
    up_part = f"{days} day{'' if days == 1 else 's'}, {hours:02d}:{minutes:02d}"
    # Small deterministic wiggle from the minute counter (no RNG import).
    wiggle = ((minutes + hours) % 5) / 100.0
    load1 = round(0.06 + wiggle, 2)
    load5 = round(0.03 + wiggle / 2, 2)
    load15 = 0.05
    return (
        f" {hostname} up {up_part},  1 user,  "
        f"load average: {load1:.2f}, {load5:.2f}, {load15:.2f}"
    )


class PersonaEngine:
    """Builds and holds the deterministic deception persona."""

    def __init__(self, config: Optional[AgentConfig] = None):
        self._config = config or get_agent_config()
        overrides = self._config.persona_overrides()
        self._persona = PersonaState(
            hostname=overrides["hostname"],
            distribution=overrides["distribution"],
            kernel=overrides["kernel"],
            arch=overrides["arch"],
            username=overrides["username"],
            uid=overrides["uid"],
            gid=overrides["gid"],
            home=f"/home/{overrides['username']}",
            shell=overrides["shell"],
            system_role=overrides["system_role"],
            organization=overrides["organization"],
            services=self._default_services(),
            packages=self._default_packages(),
        )

    # -- deterministic persona flavor -------------------------------------
    def _default_services(self) -> List[str]:
        role = self._persona_role_lower()
        services = ["ssh", "cron", "rsyslog", "systemd-resolved"]
        if "nginx" in role or "web" in role or "application" in role:
            services.extend(["nginx", "gunicorn"])
        if "database" in role or "mysql" in role or "postgres" in role:
            services.extend(["mysql", "postgresql"])
        return services

    def _default_packages(self) -> List[str]:
        role = self._persona_role_lower()
        packages = [
            "bash", "coreutils", "openssh-server", "curl", "vim-tiny", "python3"
        ]
        if "nginx" in role:
            packages.extend(["nginx-common", "gunicorn"])
        if "database" in role:
            packages.append("mysql-client")
        return packages

    def _persona_role_lower(self) -> str:
        # Avoid recursion: build a minimal role string first.
        return str(self._config.mirage_role).lower()

    # -- public API ---------------------------------------------------------
    def get_persona(self) -> PersonaState:
        """The stable persona (same object identity across calls)."""
        return self._persona

    def build_user(self) -> SimulatedUser:
        p = self._persona
        return SimulatedUser(
            username=p.username,
            uid=p.uid,
            gid=p.gid,
            home=p.home,
            shell=p.shell,
            apparent_privilege="root" if p.uid == 0 else "unprivileged user",
        )

    def build_environment_state(
        self, cwd: Optional[str] = None
    ) -> EnvironmentState:
        """Persona-derived environment state, explicitly marked as fallback.

        T3 should replace this with authoritative state via
        ``EnvironmentState(source="t3")`` when its environment/VFS layer
        exposes it (documented in T2_AGENT_CONTRACTS.md).
        """
        p = self._persona
        user = self.build_user()
        return EnvironmentState(
            hostname=p.hostname,
            os_name=p.distribution,
            kernel=p.kernel,
            arch=p.arch,
            user=user.username,
            cwd=cwd or user.home,
            home=user.home,
            services=list(p.services),
            processes=self._simulated_processes(),
            interfaces=["eth0: 10.0.20.31/24", "lo: 127.0.0.1/8"],
            installed_packages=list(p.packages),
            source="fallback_persona",
        )

    def _simulated_processes(self) -> List[str]:
        p = self._persona
        procs = [
            f"{p.username}  1234  0.0  0.1  1234  4567 ?        Ss   Jan01   0:00 /lib/systemd/systemd --user",
            f"{p.username}  1300  0.0  0.2  2345  5678 ?        S    Jan01   0:00 sshd: {p.username}@pts/0",
            "root         1     0.0  0.1  1001  2112 ?        Ss   Jan01   0:01 /sbin/init",
            "root         812   0.0  0.3  3456  6789 ?        Ss   Jan01   0:00 /usr/sbin/sshd -D",
        ]
        role = p.system_role.lower()
        if "nginx" in role:
            procs.append("root         950   0.0  0.2  2100  5400 ?        Ss   Jan01   0:00 nginx: master process")
            procs.append("www-data     951   0.0  0.1  2150  5450 ?        S    Jan01   0:00 nginx: worker process")
        return procs
