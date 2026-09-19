"""
Optional lookup against Google Safe Browsing (the real, sanctioned way to
"check with Google" - not scraping search results, which would violate
Google's Terms of Service). This is a free API: get a key from Google
Cloud Console (enable the "Safe Browsing API") and set it as the
GOOGLE_SAFE_BROWSING_API_KEY environment variable.

Design choice: this signal is used ADDITIVELY ONLY. If Safe Browsing
flags a URL, we trust it and raise the risk score. If Safe Browsing says
"not found" (i.e. clean), we do NOT lower the risk score or treat the URL
as safe - a brand-new zero-day phishing site won't be in Google's
database yet, and treating "not listed" as "safe" would silently defeat
the whole point of the ML model. Safe Browsing here only ever adds
confidence about known-bad URLs; it never overrides the model's own
judgment about unknown ones.

If no API key is configured, or the request fails/times out, this
degrades gracefully to "no opinion" - it never blocks or breaks a scan.
"""

import os
import requests

API_KEY = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
TIMEOUT_SECONDS = 2.5


def check_safe_browsing(url: str):
    """
    Returns:
      True  -> Google Safe Browsing flags this URL as malicious
      False -> checked, not flagged
      None  -> no API key configured, or the lookup failed/timed out
    """
    if not API_KEY:
        return None

    body = {
        "client": {"clientId": "phishguard-ai", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        resp = requests.post(
            ENDPOINT,
            params={"key": API_KEY},
            json=body,
            timeout=TIMEOUT_SECONDS,
        )
        if resp.status_code != 200:
            return None
        data = resp.json()
        return bool(data.get("matches"))
    except requests.RequestException as e:
        print(f"PhishGuard: Safe Browsing lookup failed for {url}: {e}")
        return None
