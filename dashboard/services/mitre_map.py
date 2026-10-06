"""MITRE ATT&CK presentation map (T4).

T3's classifier is authoritative for *categories* (SAFE/RECON/SENSITIVE/
DESTRUCTIVE/UNKNOWN) — it does not emit ATT&CK technique IDs. This module
is the single documented place where a T3 category (plus, for credential
files, the classified command evidence) is rendered as a technique ID for
the dashboard. It contains no detection logic: it maps labels.

If T3 later records explicit technique IDs in its events, those events
take precedence and this map is retired (see docs/integration/
T4_API_CONTRACT.md §4).

Reference technique IDs (ATT&CK Enterprise):
    T1046      Network Service Discovery           (nmap, netstat, ss, arp)
    T1083      File and Directory Discovery        (find, ls -R walking)
    T1005      Data from Local System              (cat of sensitive files)
    T1552.001  Unsecured Credentials: In Files     (honeytoken/canary reads)
    T1485      Data Destruction                    (rm -rf, mkfs, dd)
    T1499      Endpoint Denial of Service          (fork bombs etc.)
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True, slots=True)
class Technique:
    technique_id: str
    technique_name: str
    category: str          # the T3 category this rendering derives from


# T3 category -> technique rendering. Additive and conservative: only
# categories T3 actually defines appear here.
_CATEGORY_TECHNIQUES: dict[str, Technique] = {
    "RECON": Technique("T1046", "Network Service Discovery", "RECON"),
    "SENSITIVE": Technique("T1005", "Data from Local System", "SENSITIVE"),
    "DESTRUCTIVE": Technique("T1485", "Data Destruction", "DESTRUCTIVE"),
    "HONEYTOKEN": Technique("T1552.001", "Unsecured Credentials: Credentials In Files", "HONEYTOKEN"),
}

# Evidence-based refinement within SENSITIVE: a classified command that
# touches credential-shaped paths renders as credential access instead of
# generic local-system collection. The *category* is still T3's; only the
# presentation differs.
_CREDENTIAL_MARKERS = ("/etc/shadow", ".env", "credentials", "aws_credentials", "id_rsa")


def category_to_technique(
    category: str, evidence: str = ""
) -> Optional[Technique]:
    """Render a T3 category (+ optional command evidence) as a technique."""
    if not category:
        return None
    technique = _CATEGORY_TECHNIQUES.get(category)
    if technique is None:
        return None
    if category == "SENSITIVE" and evidence:
        lowered = evidence.lower()
        if any(m in lowered for m in _CREDENTIAL_MARKERS):
            return Technique(
                "T1552.001",
                "Unsecured Credentials: Credentials In Files",
                category,
            )
    return technique


def technique_display_rows(techniques: list) -> list[dict]:
    """Rows for the MITRE matrix table (id, name, category)."""
    return [
        {
            "Technique ID": t.technique_id,
            "Technique Name": t.technique_name,
            "Derived From": t.category,
        }
        for t in techniques
    ]
