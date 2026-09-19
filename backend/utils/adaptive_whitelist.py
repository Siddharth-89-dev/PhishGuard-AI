"""
Turns user feedback into whitelist entries - but only after a domain has
been repeatedly confirmed safe with zero contradicting reports. A single
"this is correct/legitimate" click is NOT enough to whitelist a domain:
that would let anyone bypass detection for their own phishing domain by
just clicking the feedback button a few times. Requiring multiple
uncontested confirmations raises that bar significantly.

NOTE for a real multi-user deployment: this file assumes feedback is
reasonably trustworthy (e.g. one trusted user, or feedback aggregated
across many distinct users/IPs). If you publish this publicly, promotion
should also be gated on distinct users/IPs, not just N feedback events -
otherwise one attacker submitting feedback N times from a script can still
game it. See the README's "before you publish" section.
"""

import json
import os
from urllib.parse import urlparse

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE_PATH = os.path.join(BASE_DIR, "learned_whitelist.json")

# How many uncontested "this is legitimate" confirmations a domain needs
# before it's auto-promoted to the whitelist.
PROMOTE_THRESHOLD = 3


def _registrable_domain(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    host = (urlparse(url).hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    return host


def _load_state() -> dict:
    if not os.path.exists(STATE_PATH):
        return {}
    try:
        with open(STATE_PATH, encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def _save_state(state: dict):
    with open(STATE_PATH, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, sort_keys=True)


def register_feedback(url: str, is_phishing: bool):
    """Call this from the /feedback endpoint for every submission."""
    domain = _registrable_domain(url)
    if not domain:
        return

    state = _load_state()
    entry = state.get(domain, {"confirmations": 0, "flags": 0, "promoted": False})

    if is_phishing:
        # Any "this is actually phishing" report taints the domain - it can
        # never be auto-promoted again, and loses promoted status if it had it.
        entry["flags"] += 1
        entry["promoted"] = False
    else:
        entry["confirmations"] += 1
        if entry["flags"] == 0 and entry["confirmations"] >= PROMOTE_THRESHOLD:
            entry["promoted"] = True

    state[domain] = entry
    _save_state(state)


def promoted_domains() -> set:
    state = _load_state()
    return {domain for domain, entry in state.items() if entry.get("promoted")}
