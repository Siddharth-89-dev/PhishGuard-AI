"""
PhishGuard AI - Network Egress & Data Chunking Analyzer
Analyzes browser network payloads, cross-domain form submissions,
and chunked exfiltration patterns to detect zero-day phishing sites.
"""

from urllib.parse import urlparse
import tldextract

_tld_extractor = tldextract.TLDExtract(cache_dir=False)

SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "work", "click",
    "buzz", "fit", "surf", "rest", "cam", "icu", "country", "kim",
    "party", "review", "trade", "bid", "stream", "download"
}


def _get_root_domain(url_or_host: str) -> str:
    """Extracts registered root domain (e.g., example.com from sub.example.com)."""
    if not url_or_host:
        return ""
    try:
        norm = url_or_host if "://" in url_or_host else "https://" + url_or_host
        ext = _tld_extractor(norm)
        if ext.suffix and ext.domain:
            return f"{ext.domain}.{ext.suffix}".lower()
        return (urlparse(norm).hostname or url_or_host).lower()
    except Exception:
        return url_or_host.lower()


def evaluate_network_egress(page_url: str, egress_data: dict) -> dict:
    """
    Evaluates browser network egress telemetry and computes behavioral risk.
    """
    if not egress_data or not isinstance(egress_data, dict):
        return {
            "egress_risk_score": 0.0,
            "egress_level": "Normal",
            "reasons": [],
            "total_bytes_sent": 0,
            "destinations": [],
            "cross_domain_detected": False,
            "credential_harvesting": False,
            "keystroke_chunking": False
        }

    page_root = _get_root_domain(page_url)
    total_bytes = int(egress_data.get("total_bytes_sent", 0))
    destinations = egress_data.get("exfiltrated_destinations", []) or []
    cross_origin_requests = egress_data.get("cross_origin_requests", []) or []
    has_password = bool(egress_data.get("has_password_field", False))
    has_card = bool(egress_data.get("has_credit_card_field", False))
    keystroke_chunking = bool(egress_data.get("keystroke_chunking_detected", False))
    sensitive_transmitted = bool(egress_data.get("sensitive_data_transmitted", False))

    risk_penalty = 0.0
    reasons = []
    credential_harvesting = False
    cross_domain_detected = False

    # 1. Inspect cross-domain data egress
    external_destinations = set()
    for req in cross_origin_requests:
        dest_host = (req.get("destination_host") or "").lower()
        dest_root = _get_root_domain(dest_host)

        if dest_root and dest_root != page_root:
            external_destinations.add(dest_root)
            cross_domain_detected = True

            # If passwords/cards were present or flagged in this request:
            if req.get("has_credentials") or sensitive_transmitted or (has_password and req.get("method") == "POST"):
                credential_harvesting = True
                risk_penalty = max(risk_penalty, 0.60)
                reasons.append(
                    f"Active credential exfiltration: Credentials/form data transmitted across domains to external drop host '{dest_root}'"
                )

    for dest in destinations:
        dest_root = _get_root_domain(dest)
        if dest_root and dest_root != page_root:
            external_destinations.add(dest_root)

    # 2. Keystroke micro-chunking analysis (Keyloggers)
    if keystroke_chunking:
        risk_penalty = max(risk_penalty, 0.50)
        target_str = ", ".join(list(external_destinations)[:2]) if external_destinations else "remote server"
        reasons.append(
            f"Keystroke chunking detected: Real-time user input events transmitted in micro-packets to {target_str}"
        )

    # 3. Destination Reputation Check (Suspicious TLD or Raw IP)
    for dest in external_destinations:
        ext = _tld_extractor(dest)
        if ext.suffix in SUSPICIOUS_TLDS:
            risk_penalty = min(1.0, risk_penalty + 0.25)
            reasons.append(f"Data exfiltrated to suspicious high-abuse TLD (.{ext.suffix}): {dest}")

        # Check raw IP destination
        parts = dest.split(".")
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            risk_penalty = min(1.0, risk_penalty + 0.30)
            reasons.append(f"Data exfiltrated directly to raw IP address: {dest}")

    # 4. Volume and Chunking Severity
    if total_bytes > 20000 and credential_harvesting:
        risk_penalty = min(1.0, risk_penalty + 0.10)
        reasons.append(f"High outbound exfiltration payload volume ({round(total_bytes / 1024, 1)} KB)")

    # Deduplicate reasons
    unique_reasons = list(dict.fromkeys(reasons))

    # Determine risk level
    if risk_penalty >= 0.50:
        egress_level = "Critical Threat"
    elif risk_penalty >= 0.25:
        egress_level = "Suspicious"
    else:
        egress_level = "Normal"

    penalty_val = round(min(1.0, risk_penalty), 2)
    return {
        "egress_risk_score": penalty_val,
        "egress_risk_penalty": penalty_val,
        "egress_level": egress_level,
        "reasons": unique_reasons,
        "total_bytes_sent": total_bytes,
        "destinations": sorted(list(external_destinations)),
        "cross_domain_detected": cross_domain_detected,
        "credential_harvesting": credential_harvesting,
        "keystroke_chunking": keystroke_chunking,
    }