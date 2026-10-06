"""Simulated environment (STEP 10).

Fake network hosts, services, and process tables. Everything here is
pure string generation — no sockets, no subprocess, no real I/O.
"""

import time

from .. import config
from .. import logger

log = logger.get_logger("simulated")

# --- Simulated network -------------------------------------------------------

# The fake internal network the attacker believes they landed in.
FAKE_HOSTS = {
    "10.0.2.10": {"name": "mirage", "os": "Linux 5.15", "latency": "0.00042s"},
    "10.0.2.15": {"name": "db-01", "os": "Linux 5.4", "latency": "0.00089s"},
    "10.0.2.20": {"name": "web-01", "os": "Linux 5.15", "latency": "0.00061s"},
    "10.0.2.1": {"name": "gateway", "os": "Linux 4.19", "latency": "0.00023s"},
}

FAKE_SERVICES = {
    "22": "ssh",
    "80": "http",
    "443": "https",
    "3306": "mysql",
    "5432": "postgresql",
}

# --- Simulated process table -------------------------------------------------

FAKE_PROCESSES = [
    (1, "root", "/sbin/init"),
    (2, "root", "[kthreadd]"),
    (105, "root", "/usr/sbin/sshd -D"),
    (208, "www-data", "nginx: worker process"),
    (312, "mysql", "/usr/sbin/mysqld"),
    (487, config.DEFAULT_USER, "-bash"),
]


def nmap_scan(target: str) -> str:
    """Simulated nmap output for a fake host (or a refusal for anything else)."""
    host = FAKE_HOSTS.get(target)
    if host is None:
        # Unknown targets get a generic "host down" — keeps the fiction
        # without encouraging scans of the real network.
        return (
            f"Starting Nmap 7.92 ( https://nmap.org ) at {time.ctime()}\n"
            f"Nmap scan report for {target}\n"
            "Host is down (0.00100s latency).\n"
            "Nmap done: 1 IP address (1 host down) scanned in 1.04 seconds"
        )

    port_lines = "\n".join(
        f"{port}/tcp   open  {svc}"
        for port, svc in sorted(FAKE_SERVICES.items(), key=lambda kv: int(kv[0]))
    )
    return (
        f"Starting Nmap 7.92 ( https://nmap.org ) at {time.ctime()}\n"
        f"Nmap scan report for {host['name']} ({target})\n"
        f"Host is up ({host['latency']} latency).\n"
        "PORT     STATE SERVICE\n"
        f"{port_lines}\n"
        "Nmap done: 1 IP address (1 host up) scanned in 2.34 seconds"
    )


def netstat_output() -> str:
    """Simulated netstat -tlnp output."""
    lines = ["Active Internet connections (only servers)"]
    service_rows = [
        ("tcp", "0.0.0.0:22", "0.0.0.0:*", "LISTEN", "105/sshd"),
        ("tcp", "0.0.0.0:80", "0.0.0.0:*", "LISTEN", "208/nginx"),
        ("tcp", "127.0.0.1:3306", "0.0.0.0:*", "LISTEN", "312/mysqld"),
    ]
    for proto, local, foreign, state, pid in service_rows:
        lines.append(f"{proto:6} {local:22} {foreign:22} {state:8} {pid}")
    return "\n".join(lines)


def ps_output() -> str:
    """Simulated ps aux output."""
    lines = [
        "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND"
    ]
    for pid, user, command in FAKE_PROCESSES:
        lines.append(
            f"{user:<9} {pid:>4}  0.0  0.1  {pid * 1000:>6} {pid * 100:>4} ?    Ss   09:00   0:00 {command}"
        )
    return "\n".join(lines)


def ssh_probe(host: str) -> str:
    """Simulated ssh connection attempt — never connects anywhere."""
    known = FAKE_HOSTS.get(host)
    if known:
        return (
            f"ssh: connect to host {host} port 22: Connection established\n"
            "Password authentication required"
        )
    return f"ssh: connect to host {host} port 22: Connection timed out"
