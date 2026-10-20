"""Report rendering: text, JSON, CSV, and defensive blocklist output."""
from __future__ import annotations

import csv
import io
import json
from typing import Dict, List

from .analyzer import Analysis

SEVERITY_ICONS = {"CRITICAL": "[!!]", "HIGH": "[! ]", "MEDIUM": "[* ]", "LOW": "[  ]"}


def render_text(summary: Dict[str, object]) -> str:
    lines: List[str] = []
    lines.append("=" * 62)
    lines.append("bruteradar report")
    lines.append("=" * 62)
    lines.append(f"Auth events analyzed : {summary['total_auth_events']}")
    lines.append(f"Failed logins        : {summary['failed_logins']}")
    lines.append(f"Accepted logins      : {summary['accepted_logins']}")
    lines.append(f"Attacker IPs         : {summary['attacker_ips']}")
    lines.append("")

    if summary["compromise_chains"]:
        lines.append("[!!] COMPROMISE CHAINS — accepted login after failures:")
        for chain in summary["compromise_chains"]:
            lines.append(
                f"     line {chain['line_no']}: user '{chain['user']}' ACCEPTED from "
                f"{chain['ip']} after {chain['prior_failures']} failures"
            )
        lines.append("")

    if summary["distributed_spray_users"]:
        lines.append(
            "[* ] Distributed password spray targets: "
            + ", ".join(summary["distributed_spray_users"])
        )
        lines.append("")

    lines.append("-" * 62)
    lines.append(f"{'IP':<16}{'FAILS':>6}{'USERS':>7}  {'CLASS':<20}{'SEV':<9}")
    lines.append("-" * 62)
    for attacker in summary["attackers"]:
        lines.append(
            f"{attacker['ip']:<16}{attacker['failures']:>6}{attacker['users_targeted']:>7}  "
            f"{attacker['classification']:<20}{attacker['severity']:<9}"
        )
    if not summary["attackers"]:
        lines.append("(no attackers above threshold)")
    lines.append("-" * 62)
    return "\n".join(lines)


def render_json(summary: Dict[str, object]) -> str:
    return json.dumps(summary, indent=2)


def render_csv(summary: Dict[str, object]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["ip", "failures", "accepted", "users_targeted", "classification", "severity"])
    for attacker in summary["attackers"]:
        writer.writerow(
            [
                attacker["ip"],
                attacker["failures"],
                attacker["accepted"],
                attacker["users_targeted"],
                attacker["classification"],
                attacker["severity"],
            ]
        )
    return buffer.getvalue()


def render_blocklist(summary: Dict[str, object]) -> str:
    """iptables drop rules for attacker IPs (review before applying)."""
    lines = ["# Review before applying. bruterar does not apply rules itself."]
    for attacker in summary["attackers"]:
        lines.append(f"iptables -A INPUT -s {attacker['ip']} -j DROP  # {attacker['severity']} {attacker['classification']}")
    return "\n".join(lines)


def build_report(analysis: Analysis) -> Dict[str, object]:
    return analysis.summary()
