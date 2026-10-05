"""Regenerate the README images (assets/banner.svg, assets/demo.svg).

    PYTHONPATH=src python scripts/make_assets.py

The demo image is rendered from the *real* CLI output, so it never goes stale.
"""
from __future__ import annotations

import textwrap
from html import escape
from pathlib import Path

from scamshield import Engine
from scamshield.cli import render

ASSETS = Path(__file__).resolve().parent.parent / "assets"
SANS = "Inter, 'Segoe UI', Helvetica, Arial, sans-serif"
SERIF = "Georgia, 'Iowan Old Style', 'Palatino Linotype', serif"
MONO = "ui-monospace, 'SF Mono', Menlo, Consolas, 'Liberation Mono', monospace"


def banner() -> str:
    cw, fs = 10.6, 17.6          # monospace advance and font size for the message card
    lines = [  # (text, flagged?) segments per line
        [("URGENT", 1), (": Your ", 0), ("account will be suspended", 1)],
        [("within 24 hours", 1), (". ", 0), ("Verify your account", 1)],
        [("now at ", 0), ("http://secure-hsbc-login.xyz", 1)],
    ]
    x0, y0, lh = 742, 188, 38
    card = []
    for i, segs in enumerate(lines):
        x, y = x0, y0 + i * lh
        for text, flag in segs:
            w = len(text) * cw
            if flag:
                card.append(f'<rect x="{x - 3:.1f}" y="{y - 21}" width="{w + 6:.1f}" height="28" rx="3" fill="#ffd84d"/>')
            card.append(f'<text x="{x:.1f}" y="{y}" font-family="{MONO}" font-size="{fs}" fill="#14213d" '
                        f'textLength="{w:.1f}" lengthAdjust="spacingAndGlyphs" xml:space="preserve">{escape(text)}</text>')
            x += w
    chips, cx = [], 84
    for label in ("Offline", "Private", "Multilingual", "Zero dependencies"):
        w = 26 + len(label) * 9.4
        chips.append(f'<rect x="{cx}" y="318" width="{w:.0f}" height="38" rx="19" fill="none" stroke="#6f84a8" stroke-width="1.5"/>'
                     f'<text x="{cx + w / 2:.0f}" y="343" text-anchor="middle" font-family="{SANS}" font-size="16" '
                     f'font-weight="600" fill="#dbe5f4">{label}</text>')
        cx += w + 14
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="1280" height="440" viewBox="0 0 1280 440" role="img" aria-labelledby="t d">
<title id="t">ScamShield</title>
<desc id="d">A suspicious bank message with its red flags highlighted in yellow and a Likely scam stamp.</desc>
<defs>
  <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#0b1530"/><stop offset="1" stop-color="#1b2f5c"/></linearGradient>
  <filter id="sh" x="-20%" y="-20%" width="140%" height="150%"><feDropShadow dx="0" dy="14" stdDeviation="16" flood-color="#000" flood-opacity=".4"/></filter>
</defs>
<rect width="1280" height="440" fill="url(#bg)"/>
<circle cx="1180" cy="40" r="260" fill="#ffffff" opacity=".035"/>
<circle cx="640" cy="470" r="200" fill="#ffffff" opacity=".03"/>
<g transform="translate(84 74)">
  <path d="M34 0 0 14v22c0 21 14 36 34 42 20-6 34-21 34-42V14z" fill="#ffd84d"/>
  <path d="M19 38l11 11 20-23" fill="none" stroke="#14213d" stroke-width="7" stroke-linecap="round" stroke-linejoin="round"/>
</g>
<text x="176" y="140" font-family="{SERIF}" font-size="86" font-weight="700" fill="#ffffff" letter-spacing="-2">ScamShield</text>
<text x="84" y="214" font-family="{SANS}" font-size="27" fill="#c9d6ec">Paste a suspicious message.</text>
<text x="84" y="252" font-family="{SANS}" font-size="27" fill="#c9d6ec">Get a verdict, the red flags,</text>
<text x="84" y="290" font-family="{SANS}" font-size="27" fill="#c9d6ec">and what to do next.</text>
{"".join(chips)}
<g filter="url(#sh)" transform="rotate(-2 980 220)">
  <rect x="712" y="72" width="500" height="296" rx="6" fill="#ffffff"/>
  <rect x="712" y="72" width="500" height="44" rx="6" fill="#e8edf5"/>
  <rect x="712" y="104" width="500" height="12" fill="#e8edf5"/>
  <text x="732" y="101" font-family="{SANS}" font-size="15" font-weight="600" fill="#52627a">Unknown sender, 9:41</text>
  {"".join(card)}
  <g transform="rotate(-5 1090 325)">
    <rect x="978" y="294" width="206" height="62" rx="8" fill="#ffffff" stroke="#b3122b" stroke-width="4"/>
    <text x="1081" y="326" text-anchor="middle" font-family="{SERIF}" font-size="29" font-weight="700" fill="#b3122b">Likely scam</text>
    <text x="1081" y="345" text-anchor="middle" font-family="{SANS}" font-size="14" font-weight="600" fill="#b3122b">risk score 100 / 100</text>
  </g>
</g>
</svg>
'''


def demo() -> str:
    cmd = 'scamshield check "Hi, your package is on hold. Pay a $1.99 redelivery fee at bit.ly/3xYz"'
    text = "Hi, your package is on hold. Pay a $1.99 redelivery fee at bit.ly/3xYz"
    report = Engine().analyze(text)
    raw = render(report, text, use_color=False).splitlines()
    rows = []
    for line in raw:
        for part in (textwrap.wrap(line, 96, subsequent_indent=" " * 7) or [""]):
            rows.append(part)
    lh, top = 24, 96
    height = top + len(rows) * lh + 56
    out = [f'<text x="32" y="{top - 16}" font-family="{MONO}" font-size="15.5" fill="#7fd1ae">$ <tspan fill="#e6edf7">{escape(cmd)}</tspan></text>']
    for i, row in enumerate(rows):
        y = top + 16 + i * lh
        s = row.strip()
        color, weight = "#c3cfe2", "400"
        if "ScamShield" in s:
            color, weight = "#ff7b8a", "700"
        elif s in ("Red flags", "What to do", "Good signs"):
            color, weight = "#ffffff", "700"
        elif s.startswith("found:"):
            color = "#7d8fae"
        elif s.startswith("✗"):
            color = "#f2f5fa"
        body = escape(row).replace("✗", '<tspan fill="#ff7b8a">✗</tspan>').replace("•", '<tspan fill="#ffd84d">•</tspan>')
        out.append(f'<text x="32" y="{y}" font-family="{MONO}" font-size="15.5" fill="{color}" font-weight="{weight}" xml:space="preserve">{body}</text>')
    dots = "".join(f'<circle cx="{26 + i * 22}" cy="24" r="6.5" fill="{c}"/>' for i, c in enumerate(("#ff5f57", "#febc2e", "#28c840")))
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="1000" height="{height}" viewBox="0 0 1000 {height}" role="img" aria-label="ScamShield command line output for a fake parcel-fee text">
<rect width="1000" height="{height}" rx="12" fill="#0d1526"/>
<rect width="1000" height="48" rx="12" fill="#17233d"/><rect y="30" width="1000" height="18" fill="#17233d"/>
{dots}
<text x="500" y="29" text-anchor="middle" font-family="{SANS}" font-size="14" fill="#8ea0bf">scamshield</text>
{"".join(out)}
</svg>
'''


if __name__ == "__main__":
    ASSETS.mkdir(exist_ok=True)
    (ASSETS / "banner.svg").write_text(banner(), encoding="utf-8")
    (ASSETS / "demo.svg").write_text(demo(), encoding="utf-8")
    print("wrote", ASSETS / "banner.svg", "and", ASSETS / "demo.svg")
