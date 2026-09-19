"""
Real-time domain-age lookup via WHOIS. A domain registered days or hours
ago is one of the most reliable phishing indicators in the industry -
attackers rarely reuse aged infrastructure. This can't be backfilled as a
training feature (the historical dataset URLs would return TODAY's WHOIS
data, not what it looked like at scan time, which would be meaningless/
noisy) - so it's used purely at prediction time, additively, same pattern
as safe_browsing.py: it can raise the risk score, never lower it, and it
never blocks or breaks a scan if the lookup is slow, rate-limited, or the
network is unavailable.
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import whois

_executor = ThreadPoolExecutor(max_workers=4)
LOOKUP_TIMEOUT_SECONDS = 3.0

# A domain younger than this is treated as suspicious-by-age. Kept moderate
# (not the same near-certainty as typosquat/Safe Browsing hits) since
# legitimate new sites/startups exist too - see the moderate boost applied
# in app.py rather than a hard override.
NEW_DOMAIN_THRESHOLD_DAYS = 30


def _lookup_creation_date(hostname: str):
    record = whois.whois(hostname)
    created = record.creation_date
    if isinstance(created, list):
        created = created[0] if created else None
    return created


def domain_age_days(hostname: str):
    """Returns age in days, or None if unavailable/failed/timed out."""
    if not hostname:
        return None
    try:
        future = _executor.submit(_lookup_creation_date, hostname)
        created = future.result(timeout=LOOKUP_TIMEOUT_SECONDS)
        if not created:
            return None
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        return max(0, (datetime.now(timezone.utc) - created).days)
    except Exception as e:
        print(f"PhishGuard: domain_age lookup failed for {hostname}: {e}")
        return None
