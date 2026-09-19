import ipaddress
import math
import re
from collections import Counter
from urllib.parse import urlparse
import tldextract

_tld_extractor = tldextract.TLDExtract(cache_dir=False)

SUSPICIOUS_WORDS = (
    "login", "verify", "secure", "update", "account", "bank",
    "signin", "password", "confirm", "wallet", "payment",
    "billing", "authenticate", "credential", "unlock", "support"
)

SHORTENERS = (
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd", "ow.ly",
    "cutt.ly", "rebrand.ly", "shorturl.at", "rb.gy", "t.ly", "tiny.cc",
    "v.gd", "clck.ru"
)

TARGET_BRANDS = (
    "google", "paypal", "apple", "microsoft", "amazon", "netflix",
    "facebook", "instagram", "whatsapp", "bank", "chase", "wellsfargo",
    "binance", "coinbase", "steam", "adobe", "yahoo", "outlook", "icloud"
)

SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "work", "click",
    "buzz", "fit", "surf", "rest", "cam", "icu", "country", "kim",
    "party", "review", "trade", "bid", "stream", "download"
}

def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())

def _is_ip_address(hostname: str) -> int:
    if not hostname:
        return 0
    try:
        ipaddress.ip_address(hostname.strip("[]"))
        return 1
    except ValueError:
        return 0

def extract_url_features_dict(url: str) -> dict:
    raw_url = str(url).strip()
    has_explicit_scheme = "://" in raw_url
    scheme_str = raw_url.split("://", 1)[0].lower() if has_explicit_scheme else ""

    norm_url = raw_url if has_explicit_scheme else "https://" + raw_url
    parsed = urlparse(norm_url)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    full = norm_url.lower()

    try:
        has_port = parsed.port is not None
    except ValueError:
        has_port = False

    ext = _tld_extractor(norm_url)
    subdomain = (ext.subdomain or "").lower()
    root_domain = (ext.domain or "").lower()
    suffix = (ext.suffix or "").lower()

    suffix_parts = suffix.split(".")
    is_edu_gov = int(any(p in {"edu", "gov", "ac", "mil"} for p in suffix_parts))

    # Strip www when calculating actual subdomains so www.site.com has same count as site.com
    subdomain_labels = [s for s in subdomain.split(".") if s and s != "www"]
    subdomain_count = len(subdomain_labels)

    ip = _is_ip_address(hostname)

    # Keyword matches delimited by punctuation or boundaries to reduce false positives
    suspicious_count = sum(
        bool(re.search(rf"(?:^|[-_./?=&@]){re.escape(w)}(?:$|[-_./?=&@])", full))
        for w in SUSPICIOUS_WORDS
    )

    special_count = sum(not c.isalnum() for c in hostname)
    digit_ratio = sum(c.isdigit() for c in hostname) / max(len(hostname), 1)

    # Brand masquerading: Brand appears in subdomain or path while registered domain is NOT that brand
    brand_spoofing = int(any(
        b in (subdomain + " " + path.lower()) and b not in root_domain
        for b in TARGET_BRANDS
    ))

    is_suspicious_tld = int(suffix in SUSPICIOUS_TLDS or any(suffix.endswith("." + t) for t in SUSPICIOUS_TLDS))

    has_https = 1 if (scheme_str == "https" or (not has_explicit_scheme and parsed.scheme == "https")) else 0

    return {
        "len_url": len(norm_url),
        "len_hostname": len(hostname),
        "len_path": len(path),
        "len_query": len(query),
        "count_dot": norm_url.count("."),
        "count_hyphen": norm_url.count("-"),
        "count_underscore": norm_url.count("_"),
        "count_at": norm_url.count("@"),
        "count_question": norm_url.count("?"),
        "count_equal": norm_url.count("="),
        "count_ampersand": norm_url.count("&"),
        "count_slash": norm_url.count("/"),
        "count_digits_url": sum(c.isdigit() for c in norm_url),
        "count_digits_host": sum(c.isdigit() for c in hostname),
        "count_alpha_host": sum(c.isalpha() for c in hostname),
        "special_count": special_count,
        "subdomain_count": subdomain_count,
        "has_https": has_https,
        "is_ip": ip,
        "suspicious_count": suspicious_count,
        "is_shortener": int(any(hostname == s or hostname.endswith("." + s) for s in SHORTENERS)),
        "is_edu_gov": is_edu_gov,
        "double_slash_path": int("//" in path),
        "count_percent": norm_url.count("%"),
        "entropy_hostname": round(_entropy(hostname), 4),
        "is_punycode": int("xn--" in hostname),
        "has_port": int(has_port),
        "has_hyphen_hostname": int("-" in hostname),
        "digit_ratio_hostname": round(digit_ratio, 4),
        "path_slash_count": path.count("/"),
        "brand_spoofing": brand_spoofing,
        "is_suspicious_tld": is_suspicious_tld,
        "entropy_path": round(_entropy(path), 4),
        "entropy_query": round(_entropy(query), 4),
        "short_root_domain": int(len(root_domain) <= 3 and len(root_domain) > 0),
    }

def extract_url_features(url: str):
    return list(extract_url_features_dict(url).values())
