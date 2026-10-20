"""bruteradar — SSH authentication log analysis for defenders.

Parses Linux auth logs (syslog and journalctl formats), detects brute-force
attacks, password sprays and failed-then-successful login chains, and emits
reports (text, JSON, CSV) plus blocklists. Pure standard library.
"""

__version__ = "1.0.0"
