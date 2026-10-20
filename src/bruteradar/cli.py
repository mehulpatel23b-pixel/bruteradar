"""Command-line interface: bruteradar analyze <logfile> [options]."""
from __future__ import annotations

import argparse
import sys

from .analyzer import Analysis
from .parser import parse_file
from .report import render_blocklist, render_csv, render_json, render_text


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bruteradar",
        description="Detect brute-force, password spray and compromise chains in SSH auth logs.",
    )
    parser.add_argument("logfile", help="Path to an auth.log / journalctl export (sshd lines)")
    parser.add_argument("--json", metavar="FILE", help="Write JSON report to FILE ('-' for stdout)")
    parser.add_argument("--csv", metavar="FILE", help="Write attacker CSV to FILE ('-' for stdout)")
    parser.add_argument("--blocklist", metavar="FILE", help="Write iptables drop rules to FILE ('-' for stdout)")
    parser.add_argument("--min-failures", type=int, default=5, help="Failed logins before an IP counts as attacker (default: 5)")
    parser.add_argument("--top", type=int, default=0, help="Show only top N attackers (0 = all)")
    return parser


def main(argv=None) -> int:
    args = build_arg_parser().parse_args(argv)

    try:
        events = parse_file(args.logfile)
    except OSError as exc:
        print(f"error: cannot read {args.logfile}: {exc}", file=sys.stderr)
        return 2

    analysis = Analysis(events, min_failures=args.min_failures)
    summary = analysis.summary()

    if args.top and summary["attackers"]:
        summary["attackers"] = summary["attackers"][: args.top]

    outputs = [
        (args.json, render_json(summary)),
        (args.csv, render_csv(summary)),
        (args.blocklist, render_blocklist(summary)),
    ]
    for target, content in outputs:
        if target is None:
            continue
        if target == "-":
            print(content)
        else:
            with open(target, "w", encoding="utf-8") as handle:
                handle.write(content + "\n")

    print(render_text(summary))
    return 0 if not summary["compromise_chains"] else 1


if __name__ == "__main__":
    sys.exit(main())
