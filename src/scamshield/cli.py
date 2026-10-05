"""Command line interface.

    scamshield check "Your account is suspended, verify at bit.ly/x"
    pbpaste | scamshield check --json
    scamshield serve --port 8765

Exit codes from `check`: 0 = low risk, 1 = suspicious, 2 = likely scam.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional

from . import __version__
from .engine import Engine
from .models import LIKELY_SCAM, LOW_RISK, SUSPICIOUS, Report

EXIT = {LOW_RISK: 0, SUSPICIOUS: 1, LIKELY_SCAM: 2}


def _style(use_color: bool):
    def paint(code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if use_color else text
    return paint


def render(report: Report, text: str, use_color: bool) -> str:
    p = _style(use_color)
    color = {LIKELY_SCAM: "1;31", SUSPICIOUS: "1;33", LOW_RISK: "1;32"}[report.verdict]
    lines = ["", f"  {p('1', 'ScamShield')}  {p(color, report.headline)}  "
                  f"{p('2', f'(risk score {report.score}/100)')}", ""]
    flags = [f for f in report.findings if f.weight > 0]
    good = [f for f in report.findings if f.weight < 0]
    if flags:
        lines.append(f"  {p('1', 'Red flags')}")
        for f in flags:
            lines.append(f"   {p('31', '✗')} {f.title}")
            if f.evidence:
                lines.append(f"       {p('2', 'found: ' + repr(f.evidence))}")
            lines.append(f"       {f.explanation}")
        lines.append("")
    if good:
        lines.append(f"  {p('1', 'Good signs')}")
        for f in good:
            lines.append(f"   {p('32', '✓')} {f.title}")
        lines.append("")
    lines.append(f"  {p('1', 'What to do')}")
    lines.extend(f"   • {tip}" for tip in report.advice)
    lines.append("")
    return "\n".join(lines)


def _read_message(args: argparse.Namespace) -> Optional[str]:
    if args.file:
        with open(args.file, encoding="utf-8") as fh:
            return fh.read()
    if args.text:
        return " ".join(args.text)
    if not sys.stdin.isatty():
        return sys.stdin.read()
    return None


def cmd_check(args: argparse.Namespace) -> int:
    text = _read_message(args)
    if text is None or not text.strip():
        print("scamshield: give a message as text, --file, or on stdin.", file=sys.stderr)
        return 64
    report = Engine(args.patterns).analyze(text)
    if args.json:
        print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
    else:
        use_color = sys.stdout.isatty() and "NO_COLOR" not in os.environ
        print(render(report, text, use_color))
    return EXIT[report.verdict]


def cmd_serve(args: argparse.Namespace) -> int:
    from .server import serve
    serve(args.host, args.port, Engine(args.patterns))
    return 0


def cmd_rules(args: argparse.Namespace) -> int:
    engine = Engine(args.patterns)
    for r in sorted(engine.rules, key=lambda r: (r.category, r.lang, r.id)):
        print(f"{r.id:28} {r.lang:4} {r.weight:>4}  {r.title}")
    print(f"\n{len(engine.rules)} rules loaded")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="scamshield",
                                     description="Check a message for scam red flags, offline.")
    parser.add_argument("--version", action="version", version=f"scamshield {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_patterns(p: argparse.ArgumentParser) -> None:
        p.add_argument("--patterns", action="append", default=[], metavar="FILE",
                       help="extra community pattern pack (JSON); repeatable")

    c = sub.add_parser("check", help="analyse a message")
    c.add_argument("text", nargs="*", help="the message (or use --file / stdin)")
    c.add_argument("-f", "--file", help="read the message from a file")
    c.add_argument("--json", action="store_true", help="machine-readable output")
    add_patterns(c)
    c.set_defaults(func=cmd_check)

    s = sub.add_parser("serve", help="start the local web UI and JSON API")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8765)
    add_patterns(s)
    s.set_defaults(func=cmd_serve)

    r = sub.add_parser("rules", help="list loaded rules")
    add_patterns(r)
    r.set_defaults(func=cmd_rules)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except BrokenPipeError:  # e.g. `scamshield check ... | head`
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return 0


if __name__ == "__main__":
    sys.exit(main())
