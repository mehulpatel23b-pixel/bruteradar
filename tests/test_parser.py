import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from bruteradar.parser import parse_line, parse_source  # noqa: E402


SYSLOG_FAILED = (
    "Oct 20 09:01:02 web01 sshd[1234]: Failed password for admin from 203.0.113.10 port 55210 ssh2"
)
SYSLOG_FAILED_INVALID = (
    "Oct 20 09:01:03 web01 sshd[1234]: Failed password for invalid user oracle from 203.0.113.11 port 55211 ssh2"
)
SYSLOG_ACCEPTED = (
    "Oct 20 09:01:04 web01 sshd[1234]: Accepted publickey for sara from 198.51.100.7 port 55212 ssh2"
)
ISO_FAILED = (
    "2026-10-20T09:01:05.123456+00:00 web01 sshd[1234]: "
    "Failed password for root from 192.0.2.99 port 55213 ssh2"
)
UNRELATED = "Oct 20 09:01:06 web01 CRON[1300]: (root) CMD (run-parts /etc/cron.hourly)"
SSHD_NOISY = "Oct 20 09:01:07 web01 sshd[1234]: Connection closed by 192.0.2.99 port 55214 [preauth]"


class TestParseLine(unittest.TestCase):
    def test_parses_failed_password(self):
        event = parse_line(SYSLOG_FAILED, line_no=1)
        assert event is not None
        assert event.kind == "failed"
        assert event.user == "admin"
        assert event.ip == "203.0.113.10"
        assert event.port == 55210
        assert event.invalid_user is False
        assert event.ts_raw == "Oct 20 09:01:02"

    def test_marks_invalid_users(self):
        event = parse_line(SYSLOG_FAILED_INVALID, line_no=2)
        assert event is not None
        assert event.invalid_user is True
        assert event.user == "oracle"

    def test_parses_accepted(self):
        event = parse_line(SYSLOG_ACCEPTED, line_no=3)
        assert event is not None
        assert event.kind == "accepted"
        assert event.user == "sara"
        assert event.ip == "198.51.100.7"

    def test_parses_journalctl_iso_format(self):
        event = parse_line(ISO_FAILED, line_no=4)
        assert event is not None
        assert event.kind == "failed"
        assert event.ip == "192.0.2.99"

    def test_ignores_non_sshd_lines(self):
        assert parse_line(UNRELATED, line_no=5) is None

    def test_ignores_sshd_noise_without_auth_signal(self):
        assert parse_line(SSHD_NOISY, line_no=6) is None

    def test_parses_timestamps(self):
        event = parse_line(SYSLOG_FAILED, line_no=1)
        assert event.ts is not None
        assert event.ts.minute == 1


class TestParseSource(unittest.TestCase):
    def test_parses_multiline_source(self):
        lines = [SYSLOG_FAILED, UNRELATED, SYSLOG_ACCEPTED, ""]
        events = parse_source(lines)
        assert len(events) == 2
        assert events[0].kind == "failed"
        assert events[1].kind == "accepted"

    def test_line_numbers_are_tracked(self):
        events = parse_source([UNRELATED, SYSLOG_FAILED])
        assert events[0].line_no == 2
