import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from bruteradar.analyzer import Analysis  # noqa: E402
from bruteradar.parser import parse_source  # noqa: E402


def make_log():
    lines = []
    # 203.0.113.10 — vertical brute force on 'root' (6 failures), then breaks in.
    for i in range(6):
        lines.append(
            f"Oct 20 09:0{i + 1}:00 web01 sshd[1]: Failed password for root from 203.0.113.10 port {55000 + i} ssh2"
        )
    lines.append(
        "Oct 20 09:07:00 web01 sshd[1]: Accepted password for root from 203.0.113.10 port 55007 ssh2"
    )
    # 198.51.100.44 — password spray across 12 users, 1 attempt each.
    for i, user in enumerate(["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l"]):
        lines.append(
            f"Oct 20 09:{10 + i:02d}:00 web01 sshd[1]: Failed password for {user} from 198.51.100.44 port {56000 + i} ssh2"
        )
    # 192.0.2.9 — noisy attacker, 6 users x a few tries (bruteforce bucket).
    for i in range(7):
        lines.append(
            f"Oct 20 09:2{i}:00 web01 sshd[1]: Failed password for u{i % 4} from 192.0.2.9 port {57000 + i} ssh2"
        )
    # 203.0.113.50..54 — distributed spray on user 'svc_backup' (5 attacker IPs).
    for i in range(5):
        for j in range(5):
            lines.append(
                f"Oct 20 09:3{i}:0{j} web01 sshd[1]: Failed password for svc_backup from 203.0.113.5{i} port {58000 + j} ssh2"
            )
    # 198.51.100.1 — benign single typo.
    lines.append(
        "Oct 20 09:40:00 web01 sshd[1]: Failed password for sara from 198.51.100.1 port 59000 ssh2"
    )
    return parse_source(lines)


class TestAnalysis(unittest.TestCase):
    def test_summary_counts(self):
        summary = Analysis(make_log()).summary()
        assert summary["failed_logins"] == 6 + 12 + 7 + 25 + 1
        assert summary["accepted_logins"] == 1
        assert summary["attacker_ips"] == 8  # spray IP + brute IP + 5 spray bot IPs

    def test_classifies_vertical_bruteforce(self):
        analysis = Analysis(make_log())
        assert analysis.classify("203.0.113.10") == "vertical-bruteforce"

    def test_classifies_password_spray(self):
        analysis = Analysis(make_log())
        assert analysis.classify("198.51.100.44") == "password-spray"

    def test_classifies_generic_bruteforce(self):
        analysis = Analysis(make_log())
        assert analysis.classify("192.0.2.9") == "bruteforce"

    def test_benign_ip_is_unremarkable(self):
        analysis = Analysis(make_log())
        assert analysis.classify("198.51.100.1") == "unremarkable"
        assert not analysis.is_attacker("198.51.100.1")

    def test_detects_compromise_chain(self):
        analysis = Analysis(make_log())
        assert len(analysis.compromise_chains) == 1
        chain = analysis.compromise_chains[0]
        assert chain.ip == "203.0.113.10"
        assert chain.user == "root"
        assert analysis.severity("203.0.113.10") == "CRITICAL"

    def test_detects_distributed_spray(self):
        analysis = Analysis(make_log())
        assert "svc_backup" in analysis.distributed_spray_users()

    def test_attackers_sorted_by_severity_then_volume(self):
        analysis = Analysis(make_log())
        ips = analysis.attacker_ips()
        assert ips[0] == "203.0.113.10"  # CRITICAL first

    def test_min_failures_threshold_is_configurable(self):
        analysis = Analysis(make_log(), min_failures=1)
        assert analysis.is_attacker("198.51.100.1")
