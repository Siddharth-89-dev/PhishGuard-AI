import re
from urllib.parse import urlparse

def extract_url_features(url):
    parsed = urlparse(url)

    return [
        len(url),                          # length
        url.count("."),                   # dots
        url.count("-"),                   # hyphens
        url.count("@"),                   # @
        1 if parsed.scheme == "https" else 0,  # https
        1 if re.search(r"\d+\.\d+\.\d+\.\d+", url) else 0,  # ip
        url.count("//")                   # redirects
    ]