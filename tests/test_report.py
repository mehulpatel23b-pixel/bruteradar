import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from bruteradar.analyzer import Analysis  # noqa: E402
from bruteradar.parser import parse_source  # noqa: E402
from bruteradar.report import render_blocklist, render_csv, render_json, render_text  # noqa: E402


def build_summary():
    lines = [
        "Oct 20 09:01:00 web01 sshd[1]: Failed password for root from 203.0.113.10 port 55001 ssh2",
        "Oct 20 09:02:00 web01 sshd[1]: Failed password for root from 203.0.113.10 port 55002 ssh2",
        "Oct 20 09:03:00 web01 sshd[1]: Failed password for root from 203.0.113.10 port 55003 ssh2",
        "Oct 20 09:04:00 web01 sshd[1]: Failed password for root from 203.0.113.10 port 55004 ssh2",
        "Oct 20 09:05:00 web01 sshd[1]: Failed password for root from 203.0.113.10 port 55005 ssh2",
        "Oct 20 09:06:00 web01 sshd[1]: Accepted password for root from 203.0.113.10 port 55006 ssh2",
    ]
    return Analysis(parse_source(lines)).summary()


class TestRender(unittest.TestCase):
    def test_text_report_contains_sections(self):
        text = render_text(build_summary())
        assert "bruteradar report" in text
        assert "COMPROMISE CHAINS" in text
        assert "203.0.113.10" in text

    def test_json_report_round_trips(self):
        import json

        data = json.loads(render_json(build_summary()))
        assert data["attacker_ips"] == 1
        assert data["attackers"][0]["severity"] == "CRITICAL"

    def test_csv_report_has_header_and_row(self):
        csv_text = render_csv(build_summary())
        assert csv_text.splitlines()[0].startswith("ip,failures")
        assert "203.0.113.10,5,1,1,vertical-bruteforce,CRITICAL" in csv_text

    def test_blocklist_contains_iptables_drop(self):
        blocklist = render_blocklist(build_summary())
        assert "iptables -A INPUT -s 203.0.113.10 -j DROP" in blocklist
