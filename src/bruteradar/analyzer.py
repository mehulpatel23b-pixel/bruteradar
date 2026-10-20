"""Attack analysis: aggregate Events, classify attackers, find compromise chains.

Heuristics (all thresholds configurable via Analysis kwargs):

- An IP with >= min_failures failed logins is an attacker.
- Vertical brute force: attacker whose failed attempts target <= 3 users.
- Password spray (per IP): >= min_spray_users distinct users tried and on
  average <= 2 attempts per user.
- Password spray (distributed): a single username with failures from
  >= min_spray_ips distinct attacker IPs.
- Compromise chain (CRITICAL): an accepted login from an IP that previously
  had >= min_failures failed logins in the same log.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Dict, List

from .parser import Event

DEFAULTS = {
    "min_failures": 5,
    "min_spray_users": 10,
    "min_spray_ips": 5,
    "max_users_vertical": 3,
    "max_attempts_per_user_spray": 2,
}


@dataclass
class CompromiseChain:
    """An accepted login preceded by failed logins from the same IP."""

    ip: str
    user: str
    line_no: int
    prior_failures: int


@dataclass
class Analysis:
    events: List[Event]
    min_failures: int = DEFAULTS["min_failures"]
    min_spray_users: int = DEFAULTS["min_spray_users"]
    min_spray_ips: int = DEFAULTS["min_spray_ips"]
    max_users_vertical: int = DEFAULTS["max_users_vertical"]
    max_attempts_per_user_spray: int = DEFAULTS["max_attempts_per_user_spray"]

    failures_by_ip: Dict[str, int] = field(default_factory=Counter, init=False)
    accepted_by_ip: Dict[str, int] = field(default_factory=Counter, init=False)
    users_by_ip: Dict[str, Counter] = field(default_factory=lambda: defaultdict(Counter), init=False)
    ips_by_user: Dict[str, Counter] = field(default_factory=lambda: defaultdict(Counter), init=False)
    compromise_chains: List[CompromiseChain] = field(default_factory=list, init=False)

    def __post_init__(self) -> None:
        failures_so_far: Counter = Counter()
        for event in self.events:
            if event.kind == "failed":
                self.failures_by_ip[event.ip] += 1
                self.users_by_ip[event.ip][event.user] += 1
                self.ips_by_user[event.user][event.ip] += 1
                failures_so_far[event.ip] += 1
            else:
                self.accepted_by_ip[event.ip] += 1
                if failures_so_far[event.ip] >= self.min_failures:
                    self.compromise_chains.append(
                        CompromiseChain(
                            ip=event.ip,
                            user=event.user,
                            line_no=event.line_no,
                            prior_failures=failures_so_far[event.ip],
                        )
                    )

    # -- classification -------------------------------------------------

    def is_attacker(self, ip: str) -> bool:
        return self.failures_by_ip[ip] >= self.min_failures

    def classify(self, ip: str) -> str:
        """Classify one attacking IP."""
        failures = self.failures_by_ip[ip]
        if failures < self.min_failures:
            return "unremarkable"
        users = len(self.users_by_ip[ip])
        if users >= self.min_spray_users and failures / max(users, 1) <= self.max_attempts_per_user_spray:
            return "password-spray"
        if users <= self.max_users_vertical:
            return "vertical-bruteforce"
        return "bruteforce"

    def distributed_spray_users(self) -> List[str]:
        """Usernames sprayed from many distinct attacker IPs (by failed count)."""
        candidates = []
        for user, ips in self.ips_by_user.items():
            attacking = [ip for ip in ips if self.is_attacker(ip)]
            if len(attacking) >= self.min_spray_ips:
                candidates.append(user)
        return candidates

    def severity(self, ip: str) -> str:
        if any(chain.ip == ip for chain in self.compromise_chains):
            return "CRITICAL"
        if not self.is_attacker(ip):
            return "LOW"
        if self.classify(ip) in ("password-spray", "vertical-bruteforce"):
            return "HIGH"
        return "MEDIUM"

    def attacker_ips(self) -> List[str]:
        """Attacking IPs sorted by severity, then failure count."""
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        return sorted(
            (ip for ip in self.failures_by_ip if self.is_attacker(ip)),
            key=lambda ip: (order[self.severity(ip)], -self.failures_by_ip[ip]),
        )

    # -- summaries --------------------------------------------------------

    def summary(self) -> Dict[str, object]:
        attackers = self.attacker_ips()
        return {
            "total_auth_events": len(self.events),
            "failed_logins": sum(self.failures_by_ip.values()),
            "accepted_logins": sum(self.accepted_by_ip.values()),
            "attacker_ips": len(attackers),
            "compromise_chains": [vars(c) for c in self.compromise_chains],
            "distributed_spray_users": self.distributed_spray_users(),
            "attackers": [
                {
                    "ip": ip,
                    "failures": self.failures_by_ip[ip],
                    "accepted": self.accepted_by_ip[ip],
                    "users_targeted": len(self.users_by_ip[ip]),
                    "top_users": self.users_by_ip[ip].most_common(3),
                    "classification": self.classify(ip),
                    "severity": self.severity(ip),
                }
                for ip in attackers
            ],
        }
