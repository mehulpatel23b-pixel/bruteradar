"""Log parsing: raw auth.log / journalctl lines -> Event records.

Supported line formats (line noise tolerant, host and PID ignored):

Syslog:
    Oct 20 09:01:02 host sshd[1234]: Failed password for user from 1.2.3.4 port 55210 ssh2
    Oct 20 09:01:03 host sshd[1234]: Failed password for invalid user admin from 5.6.7.8 port 55211 ssh2
    Oct 20 09:01:04 host sshd[1234]: Accepted password for sara from 1.2.3.4 port 55212 ssh2

Journalctl (-o short-iso):
    2026-10-20T09:01:02.123456+00:00 host sshd[1234]: Failed password for ...

Only Failed/Accepted password and Accepted publickey lines carry signal for
this tool; everything else is ignored. No log line is ever executed.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable, List, Optional

_IPV4 = r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
_PORT = r"port (?P<port>\d+)"

# Timestamp shapes we accept: syslog ("Oct 20 09:01:02") or journalctl short-ISO.
_TS = (
    r"[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"
    r"|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
)

_FAILED_RE = re.compile(
    rf"^\s*(?P<ts>{_TS}).*?Failed password for (?:invalid user )?(?P<user>\S+) "
    rf"from {_IPV4} {_PORT}"
)
_ACCEPTED_RE = re.compile(
    rf"^\s*(?P<ts>{_TS}).*?Accepted (?:password|publickey) for (?P<user>\S+) "
    rf"from {_IPV4} {_PORT}"
)

# "invalid user" wording lives between "for" and the username; detect separately.
_INVALID_USER_RE = re.compile(r"Failed password for invalid user ")


@dataclass
class Event:
    """One authentication-relevant log line."""

    ts_raw: str
    line_no: int
    user: str
    ip: str
    port: int
    kind: str  # "failed" or "accepted"
    invalid_user: bool = False
    ts: Optional[datetime] = field(default=None, repr=False)


def _parse_ts(ts_raw: str) -> Optional[datetime]:
    for fmt in ("%b %d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(ts_raw, fmt)
        except ValueError:
            continue
    return None


def parse_line(line: str, line_no: int = 0) -> Optional[Event]:
    """Parse a single log line into an Event, or None if not relevant."""
    if "sshd" not in line:
        return None

    failed = _FAILED_RE.search(line)
    if failed:
        return Event(
            ts_raw=failed.group("ts"),
            line_no=line_no,
            user=failed.group("user"),
            ip=failed.group("ip"),
            port=int(failed.group("port")),
            kind="failed",
            invalid_user=bool(_INVALID_USER_RE.search(line)),
            ts=_parse_ts(failed.group("ts")),
        )

    accepted = _ACCEPTED_RE.search(line)
    if accepted:
        return Event(
            ts_raw=accepted.group("ts"),
            line_no=line_no,
            user=accepted.group("user"),
            ip=accepted.group("ip"),
            port=int(accepted.group("port")),
            kind="accepted",
            ts=_parse_ts(accepted.group("ts")),
        )
    return None


def parse_source(source: Iterable[str]) -> List[Event]:
    """Parse an iterable of lines (open file, string list, str.splitlines())."""
    events: List[Event] = []
    for line_no, line in enumerate(source, start=1):
        line = line.rstrip("\n")
        if not line.strip():
            continue
        event = parse_line(line, line_no=line_no)
        if event is not None:
            events.append(event)
    return events


def parse_file(path: str) -> List[Event]:
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return parse_source(handle)
