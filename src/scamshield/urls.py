"""Find links in a message and judge how trustworthy they look.

Everything here is offline: we only inspect the *shape* of the address
(shorteners, lookalike spellings, odd endings, hidden destinations). We never
visit the link.
"""
from __future__ import annotations

import ipaddress
import re
from typing import List, Optional, Tuple
from urllib.parse import urlsplit

from .models import Finding

_TLDS = (
    "com net org info biz xyz top click icu vip cfd sbs rest support zip mov "
    "link online site shop store club work fit app co io me cc tk ml ga cf gq "
    "buzz cyou monster lk in uk us au ca de fr es it ru cn br mx ng ke za pk "
    "bd np ly gl gd ee"
).split()
_BARE = (
    r"\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(?:"
    + "|".join(sorted(_TLDS, key=len, reverse=True))
    + r")\b(?:/[^\s<>\"'`]*)?"
)
URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"'`]+|" + _BARE, re.I)

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly",
    "rb.gy", "shorturl.at", "t.ly", "rebrand.ly", "tiny.cc", "buff.ly",
    "lnkd.in", "s.id", "v.gd", "shorte.st", "bl.ink",
}
SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "icu", "vip", "cfd", "sbs", "rest", "support",
    "zip", "mov", "tk", "ml", "ga", "cf", "gq", "buzz", "cyou", "monster",
}
_SECOND_LEVEL = {"co", "com", "org", "net", "gov", "ac", "edu", "ltd", "plc"}
_AFFIXES = {
    "secure", "login", "verify", "support", "account", "update", "service",
    "services", "help", "pay", "alert", "billing", "id", "online", "team",
    "care", "refund", "wallet", "safe", "auth", "signin", "confirm", "mail",
    "web", "app", "official", "customer", "center", "centre", "my", "security",
    "bank", "banking", "portal", "claim", "rewards",
}

# (display name, lowercase key, real domains)
BRANDS: List[Tuple[str, str, Tuple[str, ...]]] = [
    ("PayPal", "paypal", ("paypal.com", "paypal.me", "paypalobjects.com")),
    ("Amazon", "amazon", ("amazon.com", "amazon.co.uk", "amazon.in", "amazon.de",
                          "amazon.ca", "amazon.com.au", "amazon.co.jp",
                          "amazonaws.com", "amzn.to", "a.co")),
    ("Apple", "apple", ("apple.com", "icloud.com")),
    ("Microsoft", "microsoft", ("microsoft.com", "microsoftonline.com", "live.com",
                                "office.com", "outlook.com")),
    ("Google", "google", ("google.com", "goo.gl", "googleapis.com", "google.co.uk",
                          "google.co.in", "googleusercontent.com", "gstatic.com")),
    ("Netflix", "netflix", ("netflix.com", "nflxext.com")),
    ("Facebook", "facebook", ("facebook.com", "fb.com", "fb.me")),
    ("Instagram", "instagram", ("instagram.com",)),
    ("WhatsApp", "whatsapp", ("whatsapp.com", "whatsapp.net", "wa.me")),
    ("DHL", "dhl", ("dhl.com", "dhl.de")),
    ("FedEx", "fedex", ("fedex.com",)),
    ("UPS", "ups", ("ups.com",)),
    ("USPS", "usps", ("usps.com",)),
    ("Royal Mail", "royalmail", ("royalmail.com",)),
    ("HSBC", "hsbc", ("hsbc.com", "hsbc.co.uk", "hsbc.com.hk", "hsbc.lk")),
    ("Chase", "chase", ("chase.com",)),
    ("Wells Fargo", "wellsfargo", ("wellsfargo.com",)),
    ("Bank of America", "bankofamerica", ("bankofamerica.com",)),
    ("Citibank", "citibank", ("citibank.com", "citi.com")),
    ("IRS", "irs", ("irs.gov",)),
    ("Paytm", "paytm", ("paytm.com",)),
    ("HDFC", "hdfc", ("hdfcbank.com", "hdfc.com")),
    ("Bank of Ceylon", "boc", ("boc.lk",)),
    ("People's Bank", "peoplesbank", ("peoplesbank.lk",)),
    ("Commercial Bank", "combank", ("combank.lk",)),
    ("HNB", "hnb", ("hnb.lk",)),
    ("Sampath Bank", "sampath", ("sampath.lk",)),
    ("Dialog", "dialog", ("dialog.lk",)),
    ("SLT-Mobitel", "slt", ("slt.lk", "sltmobitel.lk")),
    ("Mobitel", "mobitel", ("mobitel.lk",)),
]
_ALL_LEGIT = {d for _, _, ds in BRANDS for d in ds}


def _deleet_variants(token: str) -> set:
    base = token.replace("rn", "m").replace("vv", "w")
    as_l = base.translate(str.maketrans("013$5@", "oleesa"))
    as_i = base.translate(str.maketrans({"0": "o", "1": "i", "3": "e",
                                         "$": "s", "5": "s", "@": "a"}))
    return {token, as_l, as_i}


def _collapse(text: str) -> str:
    return re.sub(r"(.)\1+", r"\1", text)


def _brand_match(token: str, key: str) -> Optional[str]:
    """Return 'exact' (uses the brand name) or 'lookalike' (spoofed spelling)."""
    if token == key:
        return "exact"
    if len(key) >= 5:
        for rest in (token[len(key):] if token.startswith(key) else None,
                     token[:-len(key)] if token.endswith(key) else None):
            if rest and rest in _AFFIXES:
                return "exact"
    if len(key) >= 4:
        for variant in _deleet_variants(token):
            if variant == key or _collapse(variant) == _collapse(key):
                return "lookalike"
    return None


def _split_host(host: str) -> Optional[Tuple[str, str, str, List[str]]]:
    labels = host.split(".")
    if len(labels) < 2:
        return None
    n = 3 if (len(labels) >= 3 and len(labels[-1]) == 2
              and labels[-2] in _SECOND_LEVEL) else 2
    return ".".join(labels[-n:]), labels[-n], labels[-1], labels[:-n]


def _finding(rule_id: str, weight: int, title: str, why: str,
             raw: str, start: int) -> Finding:
    return Finding(rule_id=rule_id, category="url", weight=weight, title=title,
                   explanation=why, evidence=raw, start=start, end=start + len(raw))


def analyze_url(raw: str, start: int = -1) -> List[Finding]:
    has_scheme = raw.lower().startswith(("http://", "https://"))
    try:
        parts = urlsplit(raw if has_scheme else "http://" + raw)
        host = (parts.hostname or "").lower().rstrip(".")
    except ValueError:
        return []
    if not host:
        return []

    out: List[Finding] = []
    if parts.username is not None:
        out.append(_finding(
            "url.userinfo", 25, "Link hides its real destination",
            "Everything before the '@' in a web address is ignored by the browser. "
            "Scammers use it to make a link look like a trusted site.", raw, start))

    try:
        ipaddress.ip_address(host)
        out.append(_finding(
            "url.ip", 25, "Link points to a bare IP address",
            "Real companies use names, not numbers. This is common in phishing kits.",
            raw, start))
        return out
    except ValueError:
        pass

    if "xn--" in host:
        out.append(_finding(
            "url.punycode", 20, "Link uses look-alike characters",
            "The address contains encoded foreign letters that can imitate a real "
            "brand.", raw, start))

    split = _split_host(host)
    if split is None:
        return out
    domain, label, tld, subs = split

    if domain in SHORTENERS:
        out.append(_finding(
            "url.shortener", 12, "Shortened link",
            "A short link hides where it leads. Scammers use them to dodge filters.",
            raw, start))
    if tld in SUSPICIOUS_TLDS:
        out.append(_finding(
            "url.tld", 12, f"Unusual web address ending (.{tld})",
            f"The .{tld} ending is cheap and heavily used for throwaway scam sites.",
            raw, start))
    if len(subs) >= 3:
        out.append(_finding(
            "url.subdomains", 8, "Address has many sub-parts",
            "Long chains of sub-domains are used to bury the real site name.",
            raw, start))
    if domain not in _ALL_LEGIT and label.count("-") >= 2:
        out.append(_finding(
            "url.hyphens", 8, "Address stuffed with hyphens",
            "Names like 'secure-bank-login-update' are typical of fake sites.",
            raw, start))
    if has_scheme and raw.lower().startswith("http://"):
        out.append(_finding(
            "url.http", 5, "Link is not encrypted (http)",
            "Legitimate login and payment pages use https.", raw, start))

    if domain not in _ALL_LEGIT:
        tokens = [t for t in re.split(r"[.\-_]", host[: -len(tld) - 1]) if t]
        for name, key, _ in BRANDS:
            kind = next((k for t in tokens if (k := _brand_match(t, key))), None)
            if kind:
                why = (f"The address uses the name '{name}' but is not {name}'s real "
                       f"website ({domain})." if kind == "exact" else
                       f"The address is spelled to look like '{name}' but is "
                       f"actually {domain}.")
                out.append(_finding(f"url.brand.{key}", 30,
                                    f"Link pretends to be {name}", why, raw, start))
                break
    return out


def find_urls(text: str) -> List[Finding]:
    findings: List[Finding] = []
    seen = set()
    for m in URL_RE.finditer(text):
        if m.start() > 0 and text[m.start() - 1] == "@":
            continue  # e-mail address, not a link
        raw = m.group(0)
        while raw and raw[-1] in ".,;:!?)]}\"'":
            raw = raw[:-1]
        if not raw or (m.start(), raw) in seen:
            continue
        seen.add((m.start(), raw))
        findings.extend(analyze_url(raw, m.start()))
    return findings
