import re
from urllib.parse import urlparse

def extract_url_features(url: str):
    parsed = urlparse(url)

    url_length = len(url)
    dots = url.count(".")
    has_at = 1 if "@" in url else 0
    https = 1 if parsed.scheme == "https" else 0
    has_ip = 1 if re.search(r"\d+\.\d+\.\d+\.\d+", url) else 0
    hyphen = url.count("-")
    redirects = url.count("//")

    return [
        url_length,
        dots,
        has_at,
        https,
        has_ip,
        hyphen,
        redirects
    ]
