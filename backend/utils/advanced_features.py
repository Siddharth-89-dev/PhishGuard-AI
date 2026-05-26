import re
import socket
import requests
from urllib.parse import urlparse
import tldextract

def extract_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc

    features = {}

    # Basic features
    features["length_url"] = len(url)
    features["nb_dots"] = url.count(".")
    features["nb_hyphens"] = url.count("-")
    features["nb_at"] = url.count("@")
    features["https_token"] = 1 if parsed.scheme == "https" else 0

    # IP check
    features["ip"] = 1 if re.search(r"\d+\.\d+\.\d+\.\d+", url) else 0

    # Subdomains
    ext = tldextract.extract(url)
    features["nb_subdomains"] = len(ext.subdomain.split(".")) if ext.subdomain else 0

    # Domain length
    features["length_hostname"] = len(domain)

    # DNS check
    try:
        socket.gethostbyname(domain)
        features["dns_record"] = 1
    except:
        features["dns_record"] = 0

    # Suspicious words
    suspicious = ["login", "verify", "secure", "bank", "account"]
    features["phish_hints"] = int(any(word in url.lower() for word in suspicious))

    # Default fallback for missing features
    return features